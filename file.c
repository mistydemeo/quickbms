/*
    Copyright 2009-2017 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

// QuickBMS internal file operations (fdnum)



u64 myfilesize(int fdnum) {
    struct stat xstat;

    if(fdnum < 0) {
        return(g_memory_file[-fdnum].size);
    }
    CHECK_FILENUM
    if(g_filenumber[fdnum].fd) {
        xstat.st_size = 0;
        fstat(fileno(g_filenumber[fdnum].fd), &xstat);
        return(xstat.st_size);
    }
    // sockets and streams want the max signed value
    if(g_filenumber[fdnum].pd) return(((u_int)(-1)) >> 1);    // 0x7fffffff... return(((process_file_t *)g_filenumber[fdnum].pd)->size);
    if(g_filenumber[fdnum].vd) return(((video_file_t *)g_filenumber[fdnum].vd)->size);
    return(((u_int)(-1)) >> 1); // 0x7fffffff...
}



int fcoverage(int fdnum) {
    memory_file_t   *memfile;
    filenumber_t    *filez;
    u_int   coverage    = 0,
            fsize       = 0,
            offset      = 0;
    int     perc        = 0;

    if(fdnum < 0) {
        memfile = &g_memory_file[-fdnum];
        coverage = memfile->coverage;
        fsize    = myfilesize(fdnum);
        offset   = myftell(fdnum);
    } else {
        //CHECK_FILENUM //do NOT use it because the file can be unexistent too!
        filez = &g_filenumber[fdnum];
        coverage = filez->coverage;
        if(filez->fd) fsize = myfilesize(fdnum);
        if(filez->fd) offset = myftell(fdnum);
    }

    if(fsize) { // avoids division by zero
        perc = (u64)((u64)coverage * (u64)100) / (u64)fsize;
        fprintf(stderr,
            "  coverage file %-3d %3d%%   %-10"PRIu" %-10"PRIu" . offset %"PRIx"\n",
            (i32)fdnum,
            (i32)perc,
            coverage,
            fsize,
            offset);
    }
    return perc;
}



int myfclose(int fdnum) {
    memory_file_t   *memfile;
    filenumber_t    *filez;

    fcoverage(fdnum);

    if(g_enable_hexhtml) hexhtml_build(fdnum);

    if(fdnum < 0) {
        memfile = &g_memory_file[-fdnum];
        // do NOT free memfile->data, it can be reused
        memfile->pos  = 0;
        memfile->size = 0;
        if(memfile->hexhtml) {
            FREE(memfile->hexhtml)
            memfile->hexhtml_size = 0;
        }
    } else {
        //CHECK_FILENUM //do NOT use it because the file can be unexistent too!
        filez = &g_filenumber[fdnum];
             if(filez->fd) { FCLOSE(filez->fd);         filez->fd = NULL; }
        else if(filez->sd) { socket_close(filez->sd);   filez->sd = NULL; }
        else if(filez->pd) { process_close(filez->pd);  filez->pd = NULL; }
        else if(filez->ad) { audio_close(filez->ad);    filez->ad = NULL; }
        else if(filez->vd) { video_close(filez->vd);    filez->vd = NULL; }
        else if(filez->md) { winmsg_close(filez->md);   filez->md = NULL; }
        if(filez->hexhtml) {
            FREE(filez->hexhtml)
            filez->hexhtml_size = 0;
        }
    }
    return 0;
}



int fdnum_open(u8 *fname, int fdnum, int error) {
    static u8   filedir[PATHSZ + 1];
    socket_file_t   *sockfile;
    process_file_t  *procfile;
    audio_file_t    *audiofile;
    video_file_t    *videofile;
    winmsg_file_t   *winmsgfile;
    filenumber_t    *filez;
    u64     filesize;
    u8      tmp[32],
            *p;

    if(!fname) return 0;
    if((fdnum < 0) || !strnicmp(fname, MEMORY_FNAME, MEMORY_FNAMESZ)) {
        fprintf(stderr, "\n"
            "Error: the filenumber field is minor than 0, if you want to use MEMORY_FILE\n"
            "       you don't need to \"reopen\" it in this way, just specify MEMORY_FILE\n"
            "       as filenumber in the various commands like:\n"
            "         get VAR long MEMORY_FILE\n");
        myexit(QUICKBMS_ERROR_BMS);
    } else if(fdnum >= MAX_FILES) {
        fprintf(stderr, "\nError: the BMS script uses more files than how much supported by this tool\n");
        myexit(QUICKBMS_ERROR_BMS);
    }
    filez = &g_filenumber[fdnum];

    if(!fname[0]) { // flushing only
        if(filez->fd) fflush(filez->fd);  // flushing is a bad idea, anyway I allow to force it
        return 0;
    }

    myfclose(fdnum);

    // do NOT use memset to clear the structure
    filez->bitchr = 0;
    filez->bitpos = 0;
    filez->bitoff = 0;
    filez->coverage = 0;

    xgetcwd(filedir, PATHSZ);
    if(strchr(fname, ':') || (fname[0] == '/')) {
        fprintf(stderr, "- open input file %s\n", fname);
    } else {
        fprintf(stderr, "- open input file %s%c%s\n", filedir, PATHSLASH, fname);
    }

    // alternative input/output
    if(strstr(fname, "://")) {
        sockfile = socket_open(fname);
        if(sockfile) {
            sprintf(tmp, "%u", sockfile->port);
            re_strdup(&filez->fullname, fname, NULL);
            filez->filename = realloc(filez->filename, strlen(sockfile->host) + 1 + strlen(tmp) + 1);
            sprintf(filez->filename, "%s:%s", sockfile->host, tmp);
            re_strdup(&filez->basename, sockfile->host, NULL);
            re_strdup(&filez->fileext,  tmp, NULL);
            filez->sd       = sockfile;
            return 0;
        }

        procfile = process_open(fname);
        if(procfile) {
            sprintf(tmp, "%u", (i32)procfile->pid);
            re_strdup(&filez->fullname, fname, NULL);
            filez->filename = realloc(filez->filename, strlen(procfile->name) + 1 + strlen(tmp) + 1);
            sprintf(filez->filename, "%s:%s", procfile->name, tmp);
            re_strdup(&filez->basename, procfile->name, NULL);
            re_strdup(&filez->fileext,  tmp, NULL);
            filez->pd       = procfile;
            return 0;
        }

        audiofile = audio_open(fname);
        if(audiofile) {
            re_strdup(&filez->fullname, fname, NULL);
            re_strdup(&filez->filename, audiofile->name, NULL);
            re_strdup(&filez->basename, audiofile->name, NULL);
            re_strdup(&filez->fileext,  "", NULL);
            filez->ad       = audiofile;
            return 0;
        }

        videofile = video_open(fname);
        if(videofile) {
            re_strdup(&filez->fullname, fname, NULL);
            re_strdup(&filez->filename, videofile->name, NULL);
            re_strdup(&filez->basename, videofile->name, NULL);
            re_strdup(&filez->fileext,  "", NULL);
            filez->vd       = videofile;
            return 0;
        }

        winmsgfile = winmsg_open(fname);
        if(winmsgfile) {
            re_strdup(&filez->fullname, fname, NULL);
            re_strdup(&filez->filename, winmsgfile->name, NULL);
            re_strdup(&filez->basename, winmsgfile->name, NULL);
            re_strdup(&filez->fileext,  "", NULL);
            filez->md       = winmsgfile;
            return 0;
        }
    }

    if(g_write_mode) {
        filez->fd = xfopen(fname, "r+b");    // do NOT modify, it must be both read/write
        if(!filez->fd) {
            if(g_reimport) {
                if(error) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
                return -1;
            } else {
                fprintf(stderr, "\n"
                    "- the file %s doesn't exist.\n"
                    "  Do you want to create it from scratch (y/N)?\n"
                    "  ", fname);
                if(get_yesno(NULL) == 'y') {
                    filez->fd = xfopen(fname, "w+b"); // do NOT create new files! Use log for that
                }
                if(!filez->fd) {
                    if(error) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
                    return -1;
                }
            }
        }
        //setbuf(filez->fd, NULL);    // seems to cause only problems... mah
    } else {
        if(!strcmp(fname, "-")) {
            filez->fd = stdin;  // blah
        } else {
            filez->fd = xfopen(fname, "rb");
            if(!filez->fd) {
                if(error) STD_ERR(QUICKBMS_ERROR_FILE_READ);
                return -1;
            }
        }
    }

    fseek(filez->fd, 0, SEEK_END);
    filesize = ftell(filez->fd);
    fseek(filez->fd, 0, SEEK_SET);
#ifndef QUICKBMS64
    if(filesize > (u64)0xffffffffLL) {
        fprintf(stderr, "\n"
            "- the file is bigger than 4 gigabytes so it's not supported by QuickBMS,\n"
            "  I suggest you to answer N to the following question and using\n"
            "  quickbms_4gb_files.exe that has no limitations.\n"
            "  are you sure you want to continue in any case (y/N)?\n"
            "  ");
        if(get_yesno(NULL) != 'y') {
            if(g_continue_anyway) return -1;
            myexit(QUICKBMS_ERROR_USER);
        }
    } else if(filesize > (u64)0x7fffffffLL) {
        fprintf(stderr,
            "- the file is bigger than 2 gigabytes, it should work correctly but contact me\n"
            "  or the author of the script in case of problems or invalid extracted files\n"
            "  in case of problems try to use quickbms_4gb_files.exe\n");
    }
#endif

    if(g_enable_hexhtml) {
        hexhtml_init(fdnum, filesize);
    }

    // filesize
    //filez->filesize = filesize;

    // fullname
    p = get_fullpath_from_name(fname);
    re_strdup(&filez->fullname, p, NULL);      // allocate
    FREE(p)

    // filename
    p = get_filename(filez->fullname);
    re_strdup(&filez->filename, p, NULL);

    // prev_basename
    re_strdup(&filez->prev_basename, filez->basename, NULL);  // allocate

    // basename
    re_strdup(&filez->basename, filez->filename, NULL);  // allocate
    p = strrchr(filez->basename, '.');
    if(p) *p = 0;

    // extension
    p = get_extension(filez->filename);
    re_strdup(&filez->fileext, p, NULL);

    // filepath
    re_strdup(&filez->filepath, filez->fullname, NULL);  // allocate
    p = mystrrchrs(filez->filepath, PATH_DELIMITERS);
    if(!p) p = filez->filepath;
    *p = 0;

    // fullbasename
    re_strdup(&filez->fullbasename, filez->fullname, NULL);  // allocate
    p = mystrrchrs(filez->fullbasename, PATH_DELIMITERS);
    if(!p) p = filez->fullbasename;
    p = strrchr(p, '.');
    if(p) *p = 0;

    if(g_mex_default && !fdnum) g_mex_default_init(1);
    return 0;
}



u_int myftell(int fdnum) {
    if(fdnum < 0) {
        return(g_memory_file[-fdnum].pos);
    }
    CHECK_FILENUM
    if(g_filenumber[fdnum].fd) return(ftell(g_filenumber[fdnum].fd));
    if(g_filenumber[fdnum].sd) return(((socket_file_t  *)g_filenumber[fdnum].sd)->pos);
    if(g_filenumber[fdnum].pd) return((u_int)(((process_file_t *)g_filenumber[fdnum].pd)->pos));
    if(g_filenumber[fdnum].ad) return(((audio_file_t *)  g_filenumber[fdnum].ad)->pos);
    if(g_filenumber[fdnum].vd) return(((video_file_t *)  g_filenumber[fdnum].vd)->pos);
    if(g_filenumber[fdnum].md) return(((winmsg_file_t *) g_filenumber[fdnum].md)->pos);
    fprintf(stderr, "\n"
        "Error: I forgot to implement the myftell operation for this file type\n"
        "       contact me!\n");
    myexit(QUICKBMS_ERROR_BMS);
    return 0;
}



void bytesread_eof(int fdnum, int len) {
    int     oldoff  = 0;

    if(!fdnum) {
        oldoff = get_var32(BytesRead_idx);
        oldoff += len;
        if(oldoff < 0) oldoff = 0;
        add_var(BytesRead_idx, NULL, NULL, oldoff, sizeof(int));
        if(myftell(fdnum) >= myfilesize(fdnum)) {
        //if(myfeof(fdnum)) {   // feof doesn't work
            add_var(NotEOF_idx, NULL, NULL, 0, sizeof(int));
        }
    }
}



void post_fseek_actions(int fdnum, int diff_offset) {
#define post_fseek_actions_do(X)    { \
        (*X) += diff_offset; \
        if((*X) < 0) (*X) = 0; \
    }

    if(g_file_xor_size)   post_fseek_actions_do(g_file_xor_pos)
    if(g_file_rot_size)   post_fseek_actions_do(g_file_rot_pos)
    if(g_file_crypt_size) post_fseek_actions_do(g_file_crypt_pos)
    if(g_mex_default) bytesread_eof(fdnum, diff_offset);
}



int myfeof(int fdnum) {
    memory_file_t   *memfile    = NULL;
    int     ret = 0;

    if(fdnum < 0) {
        memfile = &g_memory_file[-fdnum];
        if(memfile->pos >= memfile->size) {
            ret = 1;
        }
    } else {
        CHECK_FILENUM
        if(g_filenumber[fdnum].fd) ret = feof(g_filenumber[fdnum].fd);
        // ret is already 0 for the others
    }
    return ret;
}



void post_fread_actions(int fdnum, u8 *data, int size) {
    int     i;

    // fdnum is used only for bytesread_eof so ignore it
    //if(!data) not needed here
    if(g_file_xor_size) {
        for(i = 0; i < size; i++) {
            data[i] ^= g_file_xor[(*g_file_xor_pos) % g_file_xor_size];
            (*g_file_xor_pos)++;
        }
    }
    if(g_file_rot_size) {
        for(i = 0; i < size; i++) {
            data[i] += g_file_rot[(*g_file_rot_pos) % g_file_rot_size];
            (*g_file_rot_pos)++;
        }
    }
    if(g_file_crypt_size) {
        perform_encryption(data, size);
    }
    if(g_mex_default) bytesread_eof(fdnum, size);
}



int myfr(int fdnum, u8 *data, int size, int quit_if_diff) {
    memory_file_t   *memfile    = NULL;
    int     len     = 0;
            //quit_if_diff    = 1;

    // if(!data) not necessary
    if(size < 0) {
        size = BUFFSZ;
        quit_if_diff = 0;
    }
    if(fdnum < 0) {
        memfile = &g_memory_file[-fdnum];
        if(!memfile->data) {
            fdnum = -fdnum;
            if(fdnum == 1) {
                fprintf(stderr, "\nError: in this script MEMORY_FILE has not been used/declared yet\n");
            } else {
                fprintf(stderr, "\nError: in this script MEMORY_FILE%d has not been used/declared yet\n", (i32)fdnum);
            }
            myexit(QUICKBMS_ERROR_BMS);
        }
        len = size;
        if((memfile->pos + size) > memfile->size) {
            len = memfile->size - memfile->pos;
        }
        memcpy(data, memfile->data + memfile->pos, len);
        memfile->pos += len;
        memfile->coverage += len;
    } else {
        CHECK_FILENUM
        if(g_filenumber[fdnum].fd) {
            len = fread(data, 1, size, g_filenumber[fdnum].fd);
            if(g_write_mode) {
                /*
                  in "r+b" mode the offsets are not synchronized so happens horrible things like:
                  - read 7 bytes, write 7 bytes... from offset 0 instead of 7
                  - file of 12 bytes, read 7, read 4, write 7... fails because can't increase size
                  the following lame solution works perfectly and solves the problem
                */
                fseek(g_filenumber[fdnum].fd, ftell(g_filenumber[fdnum].fd), SEEK_SET);
            }
        }
        else if(g_filenumber[fdnum].sd) len = socket_read(    g_filenumber[fdnum].sd, data, size);
        else if(g_filenumber[fdnum].pd) len = process_read(   g_filenumber[fdnum].pd, data, size);
        else if(g_filenumber[fdnum].ad) len = audio_read(     g_filenumber[fdnum].ad, data, size);
        else if(g_filenumber[fdnum].vd) len = video_read(     g_filenumber[fdnum].vd, data, size);
        else if(g_filenumber[fdnum].md) len = winmsg_read(    g_filenumber[fdnum].md, data, size);
        else {
            fprintf(stderr, "\n"
                "Error: I forgot to implement the myfr operation for this file type\n"
                "       contact me!\n");
            myexit(QUICKBMS_ERROR_BMS);
        }
        if(len < 0) len = 0;    // some functions may return a -1 error
        if(g_enable_hexhtml) hexhtml_add(fdnum, data, len);
        g_filenumber[fdnum].coverage += len;
    }
    if((len != size) && quit_if_diff) {
        fprintf(stderr, "\n"
            "Error: incomplete input file %d: %s\n"
            "       Can't read %"PRIu" bytes from offset %"PRIx".\n"
            "       Anyway don't worry, it's possible that the BMS script has been written\n"
            "       to exit in this way if it's reached the end of the archive so check it\n"
            "       or contact its author or verify that all the files have been extracted.\n"
            "       Please check the following coverage information to know if it's ok.\n"
            "\n",
            (i32)fdnum,
            g_filenumber[fdnum].fullname ? g_filenumber[fdnum].fullname : (u8 *)"",
            size - len,
            myftell(fdnum));

        fcoverage(fdnum);

        if(g_continue_anyway) return -1;
        myexit(QUICKBMS_ERROR_FILE_READ);
    }
    post_fread_actions(fdnum, data, len);
    return len;
}



int myfw(int fdnum, u8 *data, int size) {
    memory_file_t   *memfile    = NULL;
    int     len = 0,
            tmp;

    // if(!data) not necessary
    if(size < 0) {
        fprintf(stderr, "\n"
            "Error: problems with input file number %d, can't write negative size.\n"
            "\n", (i32)fdnum);
        if(g_continue_anyway) return -1;
        myexit(QUICKBMS_ERROR_FILE_WRITE);
    }
    post_fread_actions(-1, data, size);
    if(fdnum < 0) {
        memfile = &g_memory_file[-fdnum];
        if(!memfile->data) {
            fdnum = -fdnum;
            if(fdnum == 1) {
                fprintf(stderr, "\nError: in this script MEMORY_FILE has not been used/declared yet\n");
            } else {
                fprintf(stderr, "\nError: in this script MEMORY_FILE%d has not been used/declared yet\n", (i32)fdnum);
            }
            myexit(QUICKBMS_ERROR_BMS);
        }
        len = size;
        tmp = memfile->pos + len;
        if((tmp < memfile->pos) || (tmp < len)) ALLOC_ERR;
        if(tmp > memfile->size) {
            memfile->size = tmp;
            myalloc(&memfile->data, memfile->size, &memfile->maxsize);
        }
        memcpy(memfile->data + memfile->pos, data, len);
        memfile->pos += len;
    } else {
        CHECK_FILENUM
        if(g_filenumber[fdnum].fd) {
            // seems impossible but if you use the following script it will give no error
            //   get DUMMY long     # if you remove this line it will work
            //   put 1234  long
            // so, also for better security, I have added the -w check directly here
            if(g_write_mode) {
                len = fwrite(data, 1, size, g_filenumber[fdnum].fd);
                fflush(g_filenumber[fdnum].fd);
            }
        }
        else if(g_filenumber[fdnum].sd) len = socket_write(   g_filenumber[fdnum].sd, data, size);
        else if(g_filenumber[fdnum].pd) len = process_write(  g_filenumber[fdnum].pd, data, size);
        else if(g_filenumber[fdnum].ad) len = audio_write(    g_filenumber[fdnum].ad, data, size);
        else if(g_filenumber[fdnum].vd) len = video_write(    g_filenumber[fdnum].vd, data, size);
        else if(g_filenumber[fdnum].md) len = winmsg_write(   g_filenumber[fdnum].md, data, size);
        else {
            fprintf(stderr, "\n"
                "Error: I forgot to implement the myfw operation for this file type\n"
                "       contact me!\n");
            myexit(QUICKBMS_ERROR_BMS);
        }
    }
    if(len != size) {
        fprintf(stderr, "\n"
            "Error: problems with input file number %d, can't write %"PRIu" bytes.\n"
            "%s"
            "\n", (i32)fdnum, size - len,
            g_write_mode ? "" : "\n       you MUST use the -w option for enabling the file writing mode\n");
        if(g_continue_anyway) return -1;
        myexit(QUICKBMS_ERROR_FILE_WRITE);
    }
    return len;
}



int myfgetc(int fdnum) {
    int     c;
    u8      buff[1];

    c = myfr(fdnum, buff, 1, TRUE);
    if(c <= 0) return -1;
    return(buff[0]);
}



int myfputc(int c, int fdnum) {
    int     ret;
    u8      buff[1];

    buff[0] = c;
    ret = myfw(fdnum, buff, 1);
    if(ret < 0) return ret;
    return(c);
}



int myfseek_stream(int fdnum, u_int offset) {
    int     i;

    for(i = 0; i < offset; i++) {
        if(myfgetc(fdnum) < 0) return -1;
    }
    return 0;
}



int myfseek(int fdnum, u_int offset, int type) {
    memory_file_t   *memfile    = NULL;
    u_int   oldoff,
            oldsize;
    int     err = 0;

    if(type == SEEK_END) {
        if((int)offset > 0) offset = -offset;
    }

    oldoff = myftell(fdnum);
    oldsize = myfilesize(fdnum);
    if(fdnum < 0) {
        memfile = &g_memory_file[-fdnum];
        switch(type) {
            case SEEK_SET: memfile->pos = offset;                   break;
            case SEEK_CUR: memfile->pos += offset;                  break;
            case SEEK_END: memfile->pos = memfile->size + offset;   break;
            default: break;
        }
        if(memfile->pos < 0) memfile->pos = 0;
        if(memfile->pos > memfile->size) {
            if(g_append_mode) {
                if(g_append_mode == APPEND_MODE_APPEND) {
                    memfile->pos = memfile->size;
                } else {
                    // allocate space
                    memfile->size = memfile->pos;
                    if(memfile->size > memfile->maxsize) {
                        memfile->maxsize = memfile->size;
                        if(memfile->maxsize == -1) ALLOC_ERR;
                        memfile->data = realloc(memfile->data, memfile->maxsize + 1);
                        if(!memfile->data) STD_ERR(QUICKBMS_ERROR_MEMORY);
                        memfile->data[memfile->maxsize] = 0;
                    }
                    memset(memfile->data + oldsize, 0, memfile->size - oldsize);
                }
            } else {
                err = -1;
            }
        }
    } else {
        CHECK_FILENUM
        if(g_filenumber[fdnum].fd) {
            if(type == SEEK_SET) {
                err = fseek(g_filenumber[fdnum].fd, offset, type);
            } else {    // signed
                err = fseek(g_filenumber[fdnum].fd, (int)offset, type);
            }
            // if(g_append_mode)
            // there is probably no problem in reserving space in a file when it's used "w+b"
        } else if(g_filenumber[fdnum].sd) {
            err = myfseek_stream(fdnum, offset);    // SEEK_CUR
        } else if(g_filenumber[fdnum].pd) {
            switch(type) {
                case SEEK_SET: ((process_file_t *)g_filenumber[fdnum].pd)->pos = (void *)offset; break;
                case SEEK_CUR: ((process_file_t *)g_filenumber[fdnum].pd)->pos += offset; break;
                case SEEK_END: ((process_file_t *)g_filenumber[fdnum].pd)->pos = ((process_file_t *)g_filenumber[fdnum].pd)->base + ((process_file_t *)g_filenumber[fdnum].pd)->size + offset; break;
                default: break;
            }
        } else if(g_filenumber[fdnum].ad) {
            err = myfseek_stream(fdnum, offset);    // SEEK_CUR
        } else if(g_filenumber[fdnum].vd) {
            err = myfseek_stream(fdnum, offset);    // SEEK_CUR
        } else if(g_filenumber[fdnum].md) {
            err = myfseek_stream(fdnum, offset);    // SEEK_CUR
        } else {
            fprintf(stderr, "\n"
                "Error: I forgot to implement the myfseek operation for this file type\n"
                "       contact me!\n");
            myexit(QUICKBMS_ERROR_BMS);
        }
    }
    if(err) {
        fprintf(stderr, "\nError: [myfseek] the offset 0x%"PRIx" in the file %d can't be reached\n", offset, (i32)fdnum);
        if(g_continue_anyway) return -1;
        myexit(QUICKBMS_ERROR_FILE_READ);
    }
    post_fseek_actions(fdnum, myftell(fdnum) - oldoff);
    return 0;
}



int getxx(u8 *tmp, int bytes) {
    u_int   num;
    int     i;

    if(!tmp) return 0;
    num = 0;
    for(i = 0; i < bytes; i++) {
        if(g_endian == MYLITTLE_ENDIAN) {
            if(i >= (int)sizeof(num)) continue;
            num |= ((u_int)tmp[i] << (u_int)(i << (u_int)3));
        } else {
            if(i < (bytes - (int)sizeof(num))) continue;
            num |= ((u_int)tmp[i] << (u_int)((bytes - (u_int)1 - i) << (u_int)3));
        }
    }
    return(num);
}



int putxx(u8 *data, u_int num, int bytes) {
    int     i;

    if(!data) return 0;
    for(i = 0; i < bytes; i++) {
        if(g_endian == MYLITTLE_ENDIAN) {
            if(i < (int)sizeof(num))            data[i] = num >> (i << (u_int)3);
            else                                data[i] = 0;
        } else {
            if(i >= (bytes - (int)sizeof(num))) data[i] = num >> ((bytes - (u_int)1 - i) << (u_int)3);
            else                                data[i] = 0;
        }
    }
    return(bytes);
}



int fputxx(int fdnum, int num, int bytes) {
    u8      tmp[bytes];

    // if(!fd) do nothing, modify mywr
    putxx(tmp, num, bytes);
    return(myfw(fdnum, tmp, bytes));
}



int fgetxx(int fdnum, int bytes, int *error) {
    int     tmp_error;
    int     ret;
    u8      tmp[bytes];

    if(!error) error = &tmp_error;
    *error = 0;

    // if(!fd) do nothing, modify myfr
    ret = myfr(fdnum, tmp, bytes, TRUE);
    if(ret < 0) {
        *error = 1;
        return -1;
    }
    ret = getxx(tmp, bytes);
    if(g_endian_killer) { // reverse endianess
        g_endian = (g_endian == MYLITTLE_ENDIAN) ? MYBIG_ENDIAN : MYLITTLE_ENDIAN;
        myfseek(fdnum, -bytes, SEEK_CUR);
        fputxx(fdnum, ret, bytes);
        g_endian = (g_endian == MYLITTLE_ENDIAN) ? MYBIG_ENDIAN : MYLITTLE_ENDIAN;
    }
    return ret;
}



// how the bits reading works:
// the idea is having something that doesn't occupy much space in the file arrays (6 bytes per file)
// and that is not touched by the other functions to avoid to loose performances for a rarely used
// function so I have used the following fields:
//  bitchr = the current byte read from the file
//  bitpos = the amount of bits of bitchr that have been consumed (3 bits)
//  bitoff = the current offset, it's necessary to know if in the meantime
//           the user has changed offset and so bitpos must be resetted

u_int fd_read_bits(u_int bits, u8 *bitchr, u8 *bitpos, int fd) {
    u_int   ret = 0;
    int     i,
            t;
    u8      bc  = 0,
            bp  = 0;

    if(bitchr) bc = *bitchr;
    if(bitpos) bp = *bitpos;
    //if(bits > 32) return 0; // it's already called only for max 32 bits
    (bp) &= 7; // just for security
    for(i = 0; i < bits; i++) {
        if(!bp) {
            t = myfgetc(fd);
            bc = (t < 0) ? 0 : t;
        }
        if(g_endian == MYLITTLE_ENDIAN) { // uhmmm I don't think it's very fast... but works
            ret = (ret >> (u_int)1) | (u_int)((((u_int)bc >> (u_int)bp) & (u_int)1) << (u_int)(bits - 1));
        } else {
            ret = (ret << (u_int)1) | (u_int)((((u_int)bc << (u_int)bp) >> (u_int)7) & (u_int)1);
        }
        (bp)++;
        (bp) &= 7; // leave it here
    }
    if(bitchr) *bitchr = bc;
    if(bitpos) *bitpos = bp;
    return ret;
}



int fd_write_bits(u_int num, u_int bits, u8 *bitchr, u8 *bitpos, int fd) {
    int     i,
            t,
            bit,
            rem = 0;
    u8      bc  = 0,
            bp  = 0;

    if(bitchr) bc = *bitchr;
    if(bitpos) bp = *bitpos;
    //if(bits > 32) return 0; // it's already called only for max 32 bits
    (bp) &= 7; // just for security
    for(i = 0; i < bits; i++) {
        if(!bp) {
            if(rem) {
                myfseek(fd, -1, SEEK_CUR);
                myfputc(bc, fd);
                rem = 0;
            }
            t = myfgetc(fd);
            if(t < 0) {
                bc = 0;
                myfputc(bc, fd);
            } else {
                bc = t;
            }
        }
        if(g_endian == MYLITTLE_ENDIAN) { // uhmmm I don't think it's very fast... but works
            t = (u_int)1 << (u_int)bp;
            bit = (num >> (u_int)i) & (u_int)1;
        } else {
            t = (u_int)1 << (u_int)(7 - bp);
            bit = (num >> (u_int)((bits - i) - 1)) & 1;
        }
        if(bit) {
            bc |= t;   // put 1
        } else {
            bc &= ~t;  // put 0
        }
        (bp)++;
        (bp) &= 7; // leave it here
        rem++;
    }
    if(rem) {
        myfseek(fd, -1, SEEK_CUR);
        myfputc(bc, fd);
    }
    if(bitchr) *bitchr = bc;
    if(bitpos) *bitpos = bp;
    return i;
}



int bits2str(u8 *out, int outsz, int bits, u8 *bitchr, u8 *pos, int fd) {
    int     max8    = 8;
    u8      *o;

    if(!out) return 0;
    //outsz -= (*pos >> 3); pos is 3 bit
    if(outsz <= 0) return 0;
    if(outsz < (bits >> (int)3)) {
        bits = outsz << (int)3;
    }
    for(o = out; bits > 0; bits -= max8) {
        if(bits < 8) max8 = bits;
        *o++ = fd_read_bits(max8, bitchr, pos, fd);
    }
    return o - out;
}



int str2bits(u8 *in, int insz, int bits, u8 *bitchr, u8 *pos, int fd) {
    int     max8    = 8;
    u8      *o;

    if(!in) return 0;
    //insz -= (*pos >> 3); pos is 3 bit
    if(insz <= 0) return 0;
    if(insz < (bits >> (int)3)) {
        bits = insz << (int)3;
    }
    for(o = in; bits > 0; bits -= max8) {
        if(bits < 8) max8 = bits;
        fd_write_bits(*o++, max8, bitchr, pos, fd);
    }
    return(o - in);
}



int my_fdbits(int fdnum, u8 *out_bitchr, u8 *out_bitpos, u_int *out_bitoff, u8 in_bitchr, u8 in_bitpos, u_int in_bitoff) {
    if(fdnum < 0) {
        if(out_bitchr && out_bitpos && out_bitoff) {
            *out_bitchr = g_memory_file[-fdnum].bitchr;
            *out_bitpos = g_memory_file[-fdnum].bitpos;
            *out_bitoff = g_memory_file[-fdnum].bitoff;
        } else {
            g_memory_file[-fdnum].bitchr = in_bitchr;
            g_memory_file[-fdnum].bitpos = in_bitpos;
            g_memory_file[-fdnum].bitoff = in_bitoff;
        }
    } else {
        CHECK_FILENUM
        if(out_bitchr && out_bitpos && out_bitoff) {
            *out_bitchr = g_filenumber[fdnum].bitchr;
            *out_bitpos = g_filenumber[fdnum].bitpos;
            *out_bitoff = g_filenumber[fdnum].bitoff;
        } else {
            g_filenumber[fdnum].bitchr = in_bitchr;
            g_filenumber[fdnum].bitpos = in_bitpos;
            g_filenumber[fdnum].bitoff = in_bitoff;
        }
    }
    return 0;
}



int myatoifile(u8 *str) {   // for quick usage
    int     fdnum;

    if(str && !strnicmp(str, MEMORY_FNAME, MEMORY_FNAMESZ)) {
        fdnum = get_memory_file(str);
    } else if(str && !strnicmp(str, "ARRAY", 5)) {
        fdnum = myatoi(str + 5);
    } else {
        if(!str || !str[0]) return 0;  // default is file number 0
        if(!myisdechex_string(str)) return(MAX_FILES);  // the syntax of idstring sux!
        fdnum = myatoi(str);
    }
    //if((fdnum <= 0) || (fdnum > MAX_FILES)) {
    if((fdnum < -MAX_FILES) || (fdnum > MAX_FILES)) {
        fprintf(stderr, "\nError: [myatoifile] invalid FILE number (%d)\n", (i32)fdnum);
        myexit(QUICKBMS_ERROR_BMS);
    }
    return(fdnum);
}



int dumpa_memory_file(memory_file_t *memfile, u8 **ret_data, int size, int *ret_size) {
    u8      *data;

    data = *ret_data;
    if(size == -1) ALLOC_ERR;
    if(g_append_mode) {
               if(g_append_mode == APPEND_MODE_APPEND) {    // append
            memfile->pos   = memfile->size;
            if((memfile->size + size) < memfile->size) ALLOC_ERR;
            memfile->size += size;

        } else if(g_append_mode == APPEND_MODE_OVERWRITE) { // overwrite
            // allow goto to decide where placing the new content
            if((memfile->size + size) < memfile->size) ALLOC_ERR;
            if((memfile->pos + size) > memfile->size) memfile->size = memfile->pos + size;

        } else if(g_append_mode == APPEND_MODE_BEFORE) {    // before
            memfile->pos   = 0;
            if((memfile->size + size) < memfile->size) ALLOC_ERR;
            memfile->size += size;
        }
    } else {
        memfile->pos   = 0;
        memfile->size  = size;
    }
    if((memfile->pos + size) < memfile->pos) ALLOC_ERR;
    memfile->bitchr = 0;    // reset the bit stuff
    memfile->bitpos = 0;
    memfile->bitoff = 0;

    // the following are the new instructions for using less memory
    if(ret_size && !memfile->data && data) {
        memfile->data = data;   // direct assignment
        *ret_data = NULL;       // set to NULL, do NOT free!
        *ret_size = 0;
        goto quit;
    }

    if((u_int)memfile->size > (u_int)memfile->maxsize) {
        memfile->maxsize = memfile->size;
        if(memfile->maxsize == -1) ALLOC_ERR;
        memfile->data = realloc(memfile->data, memfile->maxsize + 1);
        if(!memfile->data) STD_ERR(QUICKBMS_ERROR_MEMORY);
        memfile->data[memfile->maxsize] = 0;
    } else if(!memfile->data && !memfile->maxsize) {    // avoids some rare problems in some rare cases
        if(memfile->maxsize == -1) ALLOC_ERR;
        memfile->data = realloc(memfile->data, memfile->maxsize + 1);
        if(!memfile->data) STD_ERR(QUICKBMS_ERROR_MEMORY);
        memfile->data[memfile->maxsize] = 0;
    }
    if(g_append_mode == APPEND_MODE_BEFORE) {
        mymemmove(memfile->data + size, memfile->data, memfile->size - size);
    }
    if(memfile->data) {
        memcpy(memfile->data + memfile->pos, data, size);

        // update positions in append mode only, just like a normal file!
        // don't do it for non-append_mode or many scripts will no longer work!
        if(g_append_mode) memfile->pos += size;
    }
quit:
    if(memfile->data) {
        // not needed, it's for a possible future usage or something else
        //memfile->data[memfile->pos + size] = 0;
        memfile->data[memfile->size] = 0;
    }
    return size;
}



u8 *rename_auto(int cnt, u8 *old_name) {
    static u8   new_name[PATHSZ + 1];
    int     i,
            len,
            extlen;
    u8      *p,
            *ext;

    // new_name and old_name can be the same because it's used in a cycle
    extlen = 0;
    ext = strrchr(old_name, '.');
    if(ext) {
        *ext++ = 0;
        extlen = strlen(ext);
    }
    len = strlen(old_name);
    if((len + 1 + 8 + 1 + extlen) >= PATHSZ) {
        sprintf(new_name, "%08x.dat", (i32)cnt);
    } else {
        if(ext) {
            p = new_name + len + 1 + 8 + 1;
            for(i = 0;; i++) {
                p[i] = ext[i];
                if(!ext[i]) break;
            }
        }
        mystrcpy(new_name, old_name, PATHSZ);
        len = strlen(new_name);
        p = new_name + len;
        sprintf(p, "_%08x", (i32)cnt);
        if(ext) p[1 + 8] = '.';
    }
    if(ext) ext[-1] = '.';
    return(new_name);
}



u8 *rename_invalid(u8 *old_name) {
    static int  new_namey = 0;
    static u8   new_namex[MULTISTATIC][PATHSZ + 1];
    FILE    *fd;
    int     i;
    u8      tmp[1 + 8 + 1],
            c,
            *p,
            *new_name;

    new_name = (u8 *)new_namex[new_namey++ % MULTISTATIC];
    new_name[0] = 0;

redo:
    if(!old_name) old_name = "noname";
    fgetz(new_name, PATHSZ, stdin,
        "\n"
        "- it's not possible to create that file due to its filename or related\n"
        "  incompatibilities (for example already exists a folder with that name), so\n"
        "  now you must choose a new filename for saving it.\n"
        "  if you press ENTER a new name will be generated automatically.\n"
        "  - old: %s\n"
        "  - new: ", old_name);
    if(!new_name[0]) {
        for(i = 0; i < (PATHSZ - sizeof(tmp)); i++) { // reserve space for integer and chars
            c = old_name[i];
            if(!c) break;
            if(myisalnum(c) || strchr(PATH_DELIMITERS ".", c)) new_name[i] = c;
            else new_name[i] = '_';
        }
        if(!i) {
            fprintf(stderr, "\nError: rename_invalid failed to automatically generate the new filename\n");
            goto redo;
        }
        new_name[i] = 0;
        p = strrchr(new_name, '.');
        if(!p) p = new_name + strlen(new_name);
        memmove(p + 1 + 8, p, strlen(p) + 1);
        for(i = 0;; i++) {
            sprintf(tmp, "_%08x", (i32)i);
            memcpy(p, tmp, 1 + 8);
            fd = xfopen(new_name, "rb");
            if(!fd) break;
            FCLOSE(fd);
        }
    }
    return(new_name);
}



int make_file_space(FILE *fd, int size) {
    static int  tmpsz   = 0;
    static u8   *tmp    = NULL;
    int     t,
            len;

    u_int   original_offset,
            offset;
    original_offset = ftell(fd);

        if(!tmp) {
            tmpsz = 1024 * 1024; // 1 megabyte
            tmp = malloc(tmpsz);
            if(!tmp) STD_ERR(QUICKBMS_ERROR_MEMORY);
        }

        for(len = 0; len < size; len += t) {
            t = tmpsz;
            if((size - len) < t) t = size - len;

            t = fread(tmp, 1, t, fd);
            if(t <= 0) break;
            offset = ftell(fd);

            fseek(fd, (offset - t) + size, SEEK_SET);

            t = fwrite(tmp, 1, t, fd);
            if(t <= 0) break;

            fseek(fd, offset, SEEK_SET);
        }
    fseek(fd, original_offset, SEEK_SET);
    return size;
}



int file_compare(FILE *fd, u8 *data, int size) {
    static int  tmpsz   = 0;
    static u8   *tmp    = NULL;
    int     t,
            len;

    if(!tmp) {
        tmpsz = 1024 * 1024; // 1 megabyte
        tmp = malloc(tmpsz);
        if(!tmp) STD_ERR(QUICKBMS_ERROR_MEMORY);
    }

    for(len = 0; len < size; len += t) {
        t = tmpsz;
        if((size - len) < t) t = size - len;
        t = fread(tmp, 1, t, fd);
        if(t <= 0) return -1;
        if(memcmp(tmp, data + len, t)) {
            return -1;
        }
    }
    return 0;
}



// log to file happens only here
int dumpa_direct_copy(int fdnum, FILE *fd, u8 *out, int size, int no_compare, u8 *fname) {
    static int  tmpsz   = 0;
    static u8   *tmp    = NULL;
    static u8   *cname  = NULL;

    struct stat xstat;
    FILE    *fdc        = NULL;
    int     t,
            len         = -1,
            do_compare,
            cres        = 0;    // 0 means ok / same file

    do_compare = g_compare_folder && !no_compare;

    if(do_compare) {
        spr(&cname, "%s%c%s", g_compare_folder, PATHSLASH, fname);
        fdc = xfopen(cname, "rb");
        if(fdc) {
            // check file size to avoid reading the whole file
            xstat.st_size = 0;
            fstat(fileno(fdc), &xstat);
            if(xstat.st_size != size) { // no need to use goto
                FCLOSE(fdc);
                cres = -1;
            }
        }
    }

    if(out) {
        // normal buffer copy
        if(do_compare) {
            if(fdc) {
                cres = file_compare(fdc, out, size);
                // if(cres < 0) break;
            }
        } else {
            len = fwrite(out, 1, size, fd);
        }
    } else {
        // direct copy
        if(!tmp) {
            tmpsz = 1024 * 1024; // 1 megabyte
            tmp = malloc(tmpsz);
            if(!tmp) STD_ERR(QUICKBMS_ERROR_MEMORY);
        }
        for(len = 0; len < size; len += t) {
            t = tmpsz;
            if((size - len) < t) t = size - len;
            t = myfr(fdnum, tmp, t, TRUE);
            if(t <= 0) break;
            if(do_compare) {
                if(fdc) {
                    cres = file_compare(fdc, tmp, t);
                    if(cres < 0) break;
                }
            } else {
                t = fwrite(tmp, 1, t, fd);
            }
            if(t <= 0) break;
        }
    }

    if(do_compare) {
        if(!fdc || (cres < 0)) {
            len = dumpa_direct_copy(fdnum, fd, out, size, 1, fname);    // do not use return or fdc doesn't get closed
        }
        /*if(fdc)*/ FCLOSE(fdc);
    }
    return len;
}



static inline void dumpa_state(int *quickbms_compression, int *quickbms_encryption, int zsize, int size, int xsize) {
    // notes:
    // encryption uses only the output buffer: memory = file_size
    // compression uses both input and output: memory = file_size * 2 (at least)
    // otherwise no memory is used

    //if(quickbms_compression) {
        *quickbms_compression = 0;
        if((zsize > 0) && (size > 0)) *quickbms_compression = 1;
    //}
    //if(quickbms_encryption) {
        *quickbms_encryption = 0;
        if(!perform_encryption(NULL, -1)) *quickbms_encryption = 1;
    //}
}



int CMD_Encryption_func(int cmd, int invert_mode);



#define ask_force_reimport(COMPRESSION, FORCE_CMD) \
                fprintf(stderr, "\n" \
                    "Error: file \"%s\"\n" \
                    "       the reimport option acts as a reimporter and so you cannot reinsert a\n" \
                    "       file if it's bigger than the original otherwise it will overwrite the\n" \
                    "       rest of the archive or cannot be loaded correctly:\n", \
                    fname); \
                    if(COMPRESSION) { \
                        fprintf(stderr, "\n" \
                            "         new size: %"PRId" uncompressed\n" \
                            "         old size: %"PRId" uncompressed\n" \
                            "\n", \
                            zsize, \
                            old_size); \
                    } else { \
                        fprintf(stderr, "\n" \
                            "         new size: %"PRId" (%"PRId" uncompressed)\n" \
                            "         old size: %"PRId" (%"PRId" uncompressed)\n" \
                            "\n", \
                            size, zsize, \
                            old_zsize, old_size); \
                    } \
                \
                fprintf(stderr, \
                    "- do you want to skip this file? (y/N/force)\n" \
                    "  y will continue with the next file\n" \
                    "  N (default) will terminate QuickBMS\n" \
                    "  force will force the reimporting of the file\n" \
                    "  "); \
                fgetz(ans, sizeof(ans), stdin, NULL); \
                if(get_yesno(ans) == 'y') { \
                    goto skip_import; \
                } else { \
                    if(!strnicmp(ans, "force", 5)) { \
                        FORCE_CMD \
                    } else { \
                        fprintf(stderr, \
                            "       now it's suggested to restore the backup of the original archive\n" \
                            "       because the current one could have been corrupted due to the\n" \
                            "       incomplete operation\n"); \
                        if(g_continue_anyway) { ret_value = -1; goto quit; } \
                        myexit(QUICKBMS_ERROR_COMPRESSION); \
                    } \
                }


                
int dumpa_xsize(int size, int xsize) {
    if(xsize <= 0) {
        // do nothing
    } else if(xsize > size) {
        // if it's already the total size
        size = xsize;
    } else if(xsize < size) {
        // if you specify the alignment size
        if(xsize && (size % xsize)) { size += (xsize - (size % xsize)); }
    }
    return size;
}



u8 *myfrx(int fdnum, int type, int *ret_num, int *error);
int myfwx(int fdnum, int varn, int type);
int dumpa_slog(int fdnum, u8 *fname, int offset, int size, int type) {
    typedef struct {    // another solution is keeping the file open
        u32     name_crc;
        i32     lines;
        int     offset;
    } slog_file_t;

    static int          slog_files  = 0;
    static slog_file_t  *slog_file  = NULL;
    static int  buffsz      = 0;
    static u8   *buff       = NULL;
    static int  slog_var    = 0;    // makes things faster

    FILE    *fd     = NULL;
    u32     name_crc;
    int     slog_idx,
            len,
            oldoff,
            tmpoff,
            error,
            datan,
            ret     = 0;
    u8      *data,
            *allocated_out = NULL,
            *out,
            tmp[NUMBERSZ + 1];

    inline void dumpa_slog_info(void) {
        int     tlen = len;
        if(tlen > 70) tlen = 70;
        if(!g_quiet) {
            //printf("%c %s (line %d): %*s\n", g_reimport ? '>' : '<', fname, slog_file[slog_idx].lines, (i32)tlen, out);
            printf("%c %d: %*s%s\n", g_reimport ? '>' : '<', slog_file[slog_idx].lines, (i32)tlen, out, (tlen == len) ? "" : "...");
        }
    }

    if(!fname) return -1;

    oldoff = myftell(fdnum);    // avoids useless warnings

    fname = clean_filename(fname, NULL);
    name_crc = mycrc(fname, -1);    // case sensitive

    if(!slog_var) {
        slog_var = add_var(0, "QUICKBMS_SLOG", "", 0, -2);
    }

    // no need to optimize because there is probably just one file
    for(slog_idx = 0; slog_idx < slog_files; slog_idx++) {
        if(slog_file[slog_idx].name_crc == name_crc) break;
    }
    if(slog_idx >= slog_files) {
        slog_file = realloc(slog_file, (slog_files + 1) * sizeof(slog_file_t));
        if(!slog_file) STD_ERR(QUICKBMS_ERROR_MEMORY);
        memset(&slog_file[slog_idx], 0, sizeof(slog_file_t));
        slog_file[slog_idx].name_crc = name_crc;
        slog_files++;
    }

    // (offset != -1) instead of (offset >= 0) allows to use almost 4Gb
    if(offset != (u_int)-1LL) {
        oldoff = myftell(fdnum);
        myfseek(fdnum, offset, SEEK_SET);
    }

    if(g_reimport) {

        if(fdnum < 0) {
            fprintf(stderr, "- MEMORY_FILEs cannot be used for strings editing, reimporting anyway\n");
        }

        fname = create_dir(fname, 0, 0, 0, 1);  // needed to avoid xfopen("/file.txt", "rb");
        fd = xfopen(fname, "rb");
        if(!fd) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);

        if(fseek(fd, slog_file[slog_idx].offset, SEEK_SET) < 0) goto quit;
        allocated_out = out = incremental_fread(fd, &len, 1, NULL);
        if(!out) goto quit;
        dumpa_slog_info();

        slog_file[slog_idx].lines++;
        slog_file[slog_idx].offset = ftell(fd);
        //FCLOSE(fd);

        len = cstring(out, out, len, NULL);

        // necessary and good for debugging so you can check it at any time
        add_var(slog_var, NULL, out, 0, len);

        if(size < 0) {
            // find the original size for filling the difference with zeroes
            tmpoff = myftell(fdnum);
            myfrx(fdnum, type, NULL, &error);
            if(error) goto quit;
            if(g_list_only || g_void_dump) goto quit_ok;
            size = myftell(fdnum) - tmpoff;
            myfseek(fdnum, tmpoff, SEEK_SET);

            // unicode is handled automatically by myfwx!
            if(myfwx(fdnum, slog_var, type) < 0) goto quit;
            len = myftell(fdnum) - tmpoff;
        } else {
            if(type == BMS_TYPE_UNICODE) {
                out = set_utf8_to_unicode(out, len, &len);
            }
            if(!out) goto quit;
            if(g_list_only || g_void_dump) goto quit_ok;
            if(myfw(fdnum, out, len) < 0) goto quit;
        }

        if(len > size) {
            fprintf(stderr, "- your string is longer than the original of %d bytes!!! Reimporting done\n", (i32)(len - size));
        }

        // zeroing the space
        for(; len < size; len++) {
            if(myfputc(0x00, fdnum) < 0) goto quit;
        }

    } else {

        if(size < 0) {
            data = myfrx(fdnum, type, &datan, &error);
            if(error) goto quit;
            if(data) size = strlen(data);
        } else {
            if(size == (u_int)-1LL) ALLOC_ERR;
            myalloc(&buff, size + 1, &buffsz);
            size = myfr(fdnum, buff, size, TRUE);
            if(size < 0) goto quit;
            buff[size] = 0;

            if(type == BMS_TYPE_UNICODE) {
                data = set_unicode_to_utf8(buff, size, &size);
            } else {
                data = buff;
            }
            if(!data) goto quit;
        }

        if(data) {
            while((size > 0) && !data[size - 1]) size--;    // remove possible useless 0x00 at the end, they will be recreated by the reimporter
            out = string_to_C(data, size, &len);
        } else {
            len = sprintf(tmp, "%"PRId"", datan);
            out = tmp;
        }
        if(!out) goto quit;

        if(!g_list_only && !g_void_dump) {
            fname = create_dir(fname, 1, 0, 0, 1);
            if(!slog_file[slog_idx].lines) {    // first line, create the file
                if(check_overwrite(fname, 0) < 0) {
                    fprintf(stderr, "- the file will not be exported (auto renaming not allowed in Slog)\n");
                    goto quit;
                }
                fd = xfopen(fname, "wb");
            } else {
                fd = xfopen(fname, "ab");
            }
            if(!fd) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);

            if(fwrite(out,    1, len, fd) != len) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
            if(fwrite("\r\n", 1, 2,   fd) != 2)   STD_ERR(QUICKBMS_ERROR_FILE_WRITE);

            slog_file[slog_idx].offset = ftell(fd);
            //FCLOSE(fd);
        }
        slog_file[slog_idx].lines++;

        add_var(slog_var, NULL, out, 0, len);
        dumpa_slog_info();
    }

quit_ok:
    ret = 0;
quit:
    if(offset != (u_int)-1LL) {
        myfseek(fdnum, oldoff, SEEK_SET);
    }
    FREE(allocated_out)
    FCLOSE(fd);
    return ret;
}



// currently the following is used only in append mode for performance reasons
typedef struct extracted_file_t {
    u8      *name;
    u64     offset;
    UT_hash_handle hh;
    struct extracted_file_t *next;
    struct extracted_file_t *prev;
} extracted_file_t;
static extracted_file_t *g_extracted_file   = NULL;



int dumpa(int fdnum, u8 *fname, u8 *varname, int offset, int size, int zsize, int xsize) {

// check if we are in append mode and the file has been already extracted
#define dumpa_name_overwrite_check \
    if(filetmp) { \
    } else { \
        for(xname = fname;;) { \
            if(g_append_mode != APPEND_MODE_NONE) { \
                HASH_FIND_STR(g_extracted_file, fname, ef); \
                if(ef) break; \
            } \
            if(mycrc(fname, -1) == last_name_crc) break; \
            t = check_overwrite(fname, 0); \
            if(!t) break; \
            if((t == -2) || g_force_rename) { \
                fname = rename_auto(++rename_cnt, xname); \
            } else { \
                goto quit; \
            } \
        } \
        last_name_crc = mycrc(fname, -1); \
    }

#define append_mode_extracted_file(X) \
    if(g_script_uses_append) { \
        HASH_FIND_STR(g_extracted_file, fname, ef); \
        if(!ef) { \
            ef = real_calloc(1, sizeof(extracted_file_t)); \
            if(!ef) STD_ERR(QUICKBMS_ERROR_MEMORY); \
            ef->name = real_malloc(strlen(fname) + 1); \
            strcpy(ef->name, fname); \
            HASH_ADD_STR(g_extracted_file, name, ef); \
        } \
        X \
    }


    //static  u8  tmpname[PATHSZ + 32 + 1] = "";  // 32 includes the dynamic extension
    static u8   *tmp_fname = NULL;
    static  int insize  = 0,    // ONLY as total allocated input size
                outsize = 0;    // ONLY as total allocated output size
    static  u8  *in     = NULL,
                *out    = NULL;

    static int  do_memfile_reimport = 0;    // -1=no, 0=?, 1=ok

    socket_file_t   *sockfile   = NULL;
    process_file_t  *procfile   = NULL;
    audio_file_t    *audiofile  = NULL;
    video_file_t    *videofile  = NULL;
    winmsg_file_t   *winmsgfile = NULL;

    memory_file_t   *memfile    = NULL;
    extracted_file_t *ef    = NULL;
    FILE    *fd             = NULL;
    u32     last_name_crc   = mycrc(NULL, 0);
    int     len             = 0,
            oldoff          = 0,
            filetmp         = 0,
            nametmp         = 0,
            direct_copy     = 0,
            quickbms_compression = 0,
            quickbms_encryption  = 0,
            //old_xsize       = 0,
            old_zsize       = 0,
            old_size        = 0,
            backup_xsize    = 0,
            backup_zsize    = 0,
            backup_size     = 0,
            old_compression_type = 0,
            new_compression_type = 0,
            non_files       = 0,
            rename_cnt      = 0,
            ret_value       = 0,
            is_folder       = 0,
            wildcard_pos    = -1,
            idx,
            t;
    u8      tmpbuff[64]     = "",
            ans[16],
            *ext,
            *tmp_ext        = NULL,
            *xname;

    if(!fname /*&& (offset < 0)*/ && (size < 0) && (zsize < 0)) {   // all must be invalid
        if(in == out) out = NULL;
        FREE(in)
        FREE(out)
        insize  = 0;
        outsize = 0;
        { ret_value = -1; goto quit; }
    }
    
    // the following is a set of filename cleaning instructions to avoid that files or data with special names are not saved
    if(fname) {
        sockfile = socket_open(fname);
        if(sockfile)    { non_files = 1; } else {
        procfile = process_open(fname);
        if(procfile)    { non_files = 1; } else {
        audiofile = audio_open(fname);
        if(audiofile)   { non_files = 1; } else {
        videofile = video_open(fname);
        if(videofile)   { non_files = 1; } else {
        winmsgfile = winmsg_open(fname);
        if(winmsgfile)  { non_files = 1; } else {
            fname = clean_filename(fname, &wildcard_pos);
        }}}}}
    }

    if(!varname) varname = "";

    if(!fname || !fname[0]) {
        if(g_input_total_files <= 1) {    // extension added by sign_ext
            spr(&tmp_fname, "%"PRIx".dat", g_extracted_files);
        } else {
            // the following works but would be good to have something generic rather than based on TEMPORARY_FILE
            xname = g_filenumber[0].basename;
            if(!stricmp(xname, TEMPORARY_FILE) && g_filenumber[0].prev_basename) xname = g_filenumber[0].prev_basename;
            spr(&tmp_fname, "%s%c%"PRIx".dat", xname, PATHSLASH, g_extracted_files);
        }
        fname = tmp_fname;
        nametmp = 1;
    } else if(wildcard_pos >= 0) {
        fname[wildcard_pos] = 0;
        if((wildcard_pos > 0) && strchr(PATH_DELIMITERS, fname[wildcard_pos - 1])) {
            spr(&tmp_fname, "%s%"PRIx".dat", fname, g_extracted_files);
        } else {
            spr(&tmp_fname, "%s.dat", fname);
        }

        // doesn't work, it's how clean_filename works
        // this code remains "as-is" in case of further development
        ext = strrchr(fname + wildcard_pos + 1, '.');
        if(ext) tmp_ext = ext + 1;

        fname = tmp_fname;
        nametmp = 1;
    }

    // handling of the output filename
    if(non_files) {
        // output non files like sockets, processes and so on
        // mem_file will be added later to skip the name check
        // do nothing

    } else if(!strnicmp(varname, MEMORY_FNAME, MEMORY_FNAMESZ) && !stricmp(varname, fname)) {
        memfile = &g_memory_file[-get_memory_file(fname)];    // yes, remember that it must be negative of negative
        if(g_verbose > 0) printf("- create a memory file from offset %"PRIx" of %"PRIu" bytes\n", offset, size);
        memfile->coverage = 0;  // reset it

    } else if(!stricmp(varname, TEMPORARY_FILE) && !stricmp(varname, fname)) {
        g_temporary_file_used = 1;    // global for final unlink
        filetmp = 1;
        if(g_verbose > 0) printf("- create a temporary file from offset %"PRIx" of %"PRIu" bytes\n", offset, size);

    } else {
        if(check_wildcards(fname, g_filter_files) < 0) goto quit;
        if(!g_reimport) {
            if(!g_quiet) printf("  %"PRIx" %-10"PRIu" %s\n", offset, size, fname);
        }
        if(g_listfd) {
            fprintf(g_listfd, "  %"PRIx" %-10"PRIu" %s\n", offset, size, fname);
            fflush(g_listfd);
        }
    }

    if(g_enable_hexhtml) hexhtml_name = fname;

    // output non files like sockets, processes and so on
    if(memfile) {
        non_files = 1;

        // this is just a work-around
        if(g_reimport && (g_append_mode == APPEND_MODE_APPEND) && (g_memfile_reimport_name >= 0)) {
            if(do_memfile_reimport >= 0) {
                fname = get_var(g_memfile_reimport_name);
                if(!g_quiet) printf("- REIMPORT MEMORY_FILE WORK-AROUND: \"%s\"\n", fname);
                ext = strrchr(fname, '.');
                if((wildcard_pos >= 0) || (ext && !ext[1])) {
                    fprintf(stderr, "\n"
                        "- reimporting of files with wildcard names is not possible\n");
                        do_memfile_reimport = -1;
                        ret_value = -1; goto quit;
                }
                if(!do_memfile_reimport) {
                    fprintf(stderr, "\n"
                        "- Do you want to use the experimental reimporting of chunked MEMORY_FILE (y/N)?\n"
                        "  ");
                    if(get_yesno(NULL) != 'y') {
                        myexit(QUICKBMS_ERROR_USER);    // exit now

                        do_memfile_reimport = -1;
                        ret_value = -1; goto quit;
                    }
                    do_memfile_reimport = 1;
                }
                ret_value = dumpa(fdnum, fname, get_varname(g_memfile_reimport_name), offset, size, zsize, xsize);
                goto quit;
            }
        }
    }

    // check if it's a folder or just a nameless file or bugged script
    if(fname[0] && strchr(PATH_DELIMITERS, fname[strlen(fname) - 1])) {
        if(!size && !zsize) {
            is_folder = 1;
        } else {
            spr(&tmp_fname, "%s%"PRIx".dat", fname, g_extracted_files);
            fname = tmp_fname;
            nametmp = 1;
        }
    }

    // list, folders, reimport and dump
    if(g_list_only && !memfile && !filetmp) { // only memfile and not non_files
        // do nothing

    } else if(is_folder) {
        // do nothing

    } else if(g_reimport && !non_files) {
        if(nametmp) {
            quick_simple_tmpname_scanner(fname, PATHSZ);
        }
        int skip_ask_force_reimport_1   = 0;    // lame
        backup_xsize = xsize;
        backup_zsize = zsize;
        backup_size  = size;
redo_import:
        fname = create_dir(fname, 0, 0, 0, 1);  // needed to avoid xfopen("/file.txt", "rb");
        if(g_reimport_zero) fd = (void *)0xdeadc0de;    // bypasses "if"
        else                fd = xfopen(fname, "rb");
        if(fd) {
            if(g_reimport_zero) {
                fd = NULL;
            } else {
                append_mode_extracted_file(
                    {
                        fseek(fd, ef->offset, SEEK_SET);
                    }
                )
            }

            if(fdnum < 0) {
                if(do_memfile_reimport > 0) goto quit;
                fprintf(stderr, "\nError: script invalid for reimporting, it uses MEMORY_FILEs\n");
                if(g_continue_anyway) { ret_value = -1; goto quit; }
                myexit(QUICKBMS_ERROR_BMS);
            }
            oldoff = myftell(fdnum);
            myfseek(fdnum, offset, SEEK_SET);
            dumpa_state(&quickbms_compression, &quickbms_encryption, backup_zsize, backup_size, backup_xsize);

            //old_xsize = backup_xsize;
            old_zsize = backup_zsize;
            old_size  = backup_size;

            // never use size/zsize, only backup_size/zsize are correct

            if(g_reimport_zero) {
                size = 0;
                if(quickbms_compression) {
                } else {
                    old_zsize = old_size; 
                }
                t = 1024 * 1024;
                myalloc(&out, t,  &outsize);
                memset(out, 0, t);
                while(old_zsize) {
                    if(old_zsize < t) t = old_zsize;
                    myfw(fdnum, out, t);
                    old_zsize -= t;
                }
                goto skip_import;
            }

            // experimental
            // nothing to do here, just ignore any error/warning
            // remember that often it's used "log NAME 0 0" to initialize the file so it's not possible
            // to use "if(g_append_mode != APPEND_MODE_NONE)"
            // unfortunately there are no alternatives at the moment
            if(g_script_uses_append && !offset && !backup_size) {   // log NAME 0 0
                // do nothing
            } else if(g_append_mode != APPEND_MODE_NONE) {  // we are in append mode!
                // do nothing
            } else {
                fseek(fd, 0, SEEK_END);
                size = ftell(fd);
                fseek(fd, 0, SEEK_SET);
            }

            zsize = size;
            myalloc(&out, size,  &outsize); // will be allocated by perform_compression
            if(quickbms_compression) {

                if(zsize > old_size) {
                    if(!skip_ask_force_reimport_1) {
                        ask_force_reimport(1,
                            old_size = zsize;
                        )
                        skip_ask_force_reimport_1 = 1;
                    }
                }

                myalloc(&in,  zsize, &insize);
                zsize = fread(in, 1, zsize, fd);
                old_compression_type = g_compression_type;
                switch(g_compression_type) {
                    #define QUICK_COMP_COMPRESS(X) \
                        case COMP_##X: g_compression_type = COMP_##X##_COMPRESS; break;
                    case COMP_NONE:             g_compression_type = COMP_COPY;             break;
                    case COMP_COPY:             g_compression_type = COMP_COPY;             break;
                    case COMP_NOP:              g_compression_type = COMP_COPY;             break;
                    case COMP_ZLIB_NOERROR:     g_compression_type = COMP_ZLIB_COMPRESS;    break;
                    case COMP_UNZIP_DYNAMIC:    g_compression_type = COMP_ZLIB_COMPRESS;    break;  // ???
                    case COMP_DEFLATE_NOERROR:  g_compression_type = COMP_DEFLATE_COMPRESS; break;
                    case COMP_LZMA_DYNAMIC:     g_compression_type = COMP_LZMA_COMPRESS;    break;  // ???
                    case COMP_LZMA2_DYNAMIC:    g_compression_type = COMP_LZMA2_COMPRESS;   break;  // ???
                    case COMP_STALKER_LZA:      g_compression_type = COMP_LZHUFXR_COMPRESS; break;
                    case COMP_PUYO_LZ01:        g_compression_type = COMP_LZSS0_COMPRESS;   break;
                    case COMP_RNCb:             // ???
                    case COMP_RNCb_RAW:         // ???
                    //case COMP_RNCc:             // ???
                    case COMP_RNCc_RAW:         // ???
                    case COMP_RNC_RAW:          // ???
                    case COMP_SCUMMVM6:
                    case COMP_SCUMMVM7:         g_compression_type = COMP_RNC_COMPRESS;     break;
                    case COMP_DEFLATEX:         g_compression_type = COMP_DEFLATE_COMPRESS; break;
                    case COMP_ZLIBX:            g_compression_type = COMP_ZLIB_COMPRESS;    break;
                    case COMP_SYNLZ1partial:    g_compression_type = COMP_SYNLZ1_COMPRESS;  break;
                    case COMP_SYNLZ1b:          g_compression_type = COMP_SYNLZ1_COMPRESS;  break;
                    QUICK_COMP_COMPRESS(ZLIB)
                    QUICK_COMP_COMPRESS(DEFLATE)
                    QUICK_COMP_COMPRESS(LZO1)
                    QUICK_COMP_COMPRESS(LZO1X)
                    QUICK_COMP_COMPRESS(LZO2A)
                    QUICK_COMP_COMPRESS(XMEMLZX)
                    QUICK_COMP_COMPRESS(BZIP2)
                    QUICK_COMP_COMPRESS(GZIP)
                    QUICK_COMP_COMPRESS(LZSS)
                    QUICK_COMP_COMPRESS(SFL_BLOCK)
                    QUICK_COMP_COMPRESS(SFL_RLE)
                    QUICK_COMP_COMPRESS(SFL_NULLS)
                    QUICK_COMP_COMPRESS(SFL_BITS)
                    QUICK_COMP_COMPRESS(LZF)
                    QUICK_COMP_COMPRESS(BRIEFLZ)
                    QUICK_COMP_COMPRESS(JCALG)
                    QUICK_COMP_COMPRESS(BCL_HUF)
                    QUICK_COMP_COMPRESS(BCL_LZ)
                    QUICK_COMP_COMPRESS(BCL_RICE)
                    QUICK_COMP_COMPRESS(BCL_RLE)
                    QUICK_COMP_COMPRESS(BCL_SF)
                    QUICK_COMP_COMPRESS(SZIP)
                    QUICK_COMP_COMPRESS(HUFFMANLIB)
                    QUICK_COMP_COMPRESS(LZMA)
                    QUICK_COMP_COMPRESS(LZMA_86HEAD)
                    QUICK_COMP_COMPRESS(LZMA_86DEC)
                    QUICK_COMP_COMPRESS(LZMA_86DECHEAD)
                    QUICK_COMP_COMPRESS(LZMA_EFS)
                    QUICK_COMP_COMPRESS(FALCOM)
                    case COMP_KZIP_ZLIB_COMPRESS:       break;  // it's a compression-only algorithm
                    case COMP_KZIP_DEFLATE_COMPRESS:    break;  // it's a compression-only algorithm
                    case COMP_EXECUTE: break;   // remains the same, I can do nothing for it
                    QUICK_COMP_COMPRESS(PRS)
                    QUICK_COMP_COMPRESS(RNC)
                    QUICK_COMP_COMPRESS(LZ4)
                    QUICK_COMP_COMPRESS(SFL_BLOCK_CHUNKED)
                    QUICK_COMP_COMPRESS(SNAPPY)
                    QUICK_COMP_COMPRESS(ZPAQ)
                    QUICK_COMP_COMPRESS(BLOSC)
                    QUICK_COMP_COMPRESS(GIPFELI)
                    QUICK_COMP_COMPRESS(YAPPY)
                    QUICK_COMP_COMPRESS(LZG)
                    QUICK_COMP_COMPRESS(DOBOZ)
                    QUICK_COMP_COMPRESS(NITROSDK)
                    QUICK_COMP_COMPRESS(HEX)
                    QUICK_COMP_COMPRESS(BASE64)
                    QUICK_COMP_COMPRESS(LZMA2)
                    QUICK_COMP_COMPRESS(LZMA2_86HEAD)
                    QUICK_COMP_COMPRESS(LZMA2_86DEC)
                    QUICK_COMP_COMPRESS(LZMA2_86DECHEAD)
                    QUICK_COMP_COMPRESS(LZMA2_EFS)
                    QUICK_COMP_COMPRESS(LZMA_0)
                    QUICK_COMP_COMPRESS(LZMA2_0)
                    QUICK_COMP_COMPRESS(STORMHUFF)
                    QUICK_COMP_COMPRESS(CT_HughesTransform)
                    QUICK_COMP_COMPRESS(CT_LZ77)
                    QUICK_COMP_COMPRESS(CT_ELSCoder)
                    QUICK_COMP_COMPRESS(CT_RefPack)
                    QUICK_COMP_COMPRESS(DK2)
                    QUICK_COMP_COMPRESS(QFS)
                    QUICK_COMP_COMPRESS(LZHUFXR)
                    QUICK_COMP_COMPRESS(FSE)
                    QUICK_COMP_COMPRESS(ZSTD)
                    QUICK_COMP_COMPRESS(DS_BLZ)
                    QUICK_COMP_COMPRESS(DS_HUF)
                    QUICK_COMP_COMPRESS(DS_LZE)
                    QUICK_COMP_COMPRESS(DS_LZS)
                    QUICK_COMP_COMPRESS(DS_LZX)
                    QUICK_COMP_COMPRESS(DS_RLE)
                    QUICK_COMP_COMPRESS(HEATSHRINK)
                    QUICK_COMP_COMPRESS(SMAZ)
                    QUICK_COMP_COMPRESS(LZFX)
                    QUICK_COMP_COMPRESS(PITHY)
                    QUICK_COMP_COMPRESS(ZLING)
                    QUICK_COMP_COMPRESS(DENSITY)
                    QUICK_COMP_COMPRESS(BSC)
                    QUICK_COMP_COMPRESS(SHOCO)
                    QUICK_COMP_COMPRESS(WFLZ)
                    QUICK_COMP_COMPRESS(FASTARI)
                    QUICK_COMP_COMPRESS(DICKY)
                    QUICK_COMP_COMPRESS(SQUISH)
                    QUICK_COMP_COMPRESS(LZHL)
                    QUICK_COMP_COMPRESS(LZHAM)
                    QUICK_COMP_COMPRESS(TRLE)
                    QUICK_COMP_COMPRESS(SRLE)
                    QUICK_COMP_COMPRESS(MRLE)
                    QUICK_COMP_COMPRESS(CPK)
                    QUICK_COMP_COMPRESS(LZRW1KH)
                    QUICK_COMP_COMPRESS(BPE)
                    QUICK_COMP_COMPRESS(NRV2b)
                    QUICK_COMP_COMPRESS(NRV2d)
                    QUICK_COMP_COMPRESS(NRV2e)
                    QUICK_COMP_COMPRESS(LZSS0)
                    QUICK_COMP_COMPRESS(CLZW)
                    QUICK_COMP_COMPRESS(QUICKLZ)
                    QUICK_COMP_COMPRESS(PKWARE_DCL)
                    QUICK_COMP_COMPRESS(LZ5)
                    QUICK_COMP_COMPRESS(YALZ77)
                    QUICK_COMP_COMPRESS(SYNLZ1)
                    QUICK_COMP_COMPRESS(SYNLZ2)
                    QUICK_COMP_COMPRESS(PPMZ2)
                    QUICK_COMP_COMPRESS(EA_JDLZ)
                    QUICK_COMP_COMPRESS(OODLE)
                    QUICK_COMP_COMPRESS(LZFSE)
                    QUICK_COMP_COMPRESS(M99CODER)
                    QUICK_COMP_COMPRESS(LZ4X)
                    QUICK_COMP_COMPRESS(YUKE_BPE)
                    QUICK_COMP_COMPRESS(LZO1A)
                    QUICK_COMP_COMPRESS(LZO1B)
                    QUICK_COMP_COMPRESS(LZO1C)
                    QUICK_COMP_COMPRESS(LZO1F)
                    QUICK_COMP_COMPRESS(LZO1Y)
                    QUICK_COMP_COMPRESS(LZO1Z)
                    QUICK_COMP_COMPRESS(LIZARD)
                    default: {
                        if(g_compression_type < COMP_NOP) { // if it's already a compression algorithm, continue
                            fprintf(stderr, "\nError: unsupported compression %d in reimport mode\n", (i32)g_compression_type);
                            if(g_continue_anyway) { ret_value = -1; goto quit; }
                            myexit(QUICKBMS_ERROR_COMPRESSION);
                        }
                        break;
                    }
                }
                size = perform_compression(in, zsize, &out, size, &outsize, offset);
                new_compression_type = g_compression_type;
                g_compression_type = old_compression_type;
                if(size < 0) {
                    fprintf(stderr, "\n"
                        "Error: there is an error with the recompression\n"
                        "       the returned output size is negative (%"PRId")\n", size);
                    if(g_continue_anyway) { ret_value = -1; goto quit; }
                    myexit(QUICKBMS_ERROR_COMPRESSION);
                }
            } else {
                old_zsize = old_size;   // avoid boring "if" during the check of the size
                size = fread(out, 1, size, fd);
            }

            if(g_script_uses_append) {
                if(ef) ef->offset = ftell(fd);
            }
            FCLOSE(fd);

            // mainly for block ciphers, but also for cleaning the data
            // size and old_zsize are correct, check the next comment
            if(size < old_zsize) {
                myalloc(&out, old_zsize,  &outsize);
                memset(out + size, 0, old_zsize - size);
                size = old_zsize;
            }
            g_encrypt_mode = !g_encrypt_mode;   // this job is already done by CMD_Encryption_func
            CMD_Encryption_func(-1, 1);
            size = perform_encryption(out, size);
            g_encrypt_mode = !g_encrypt_mode;
            if(size == -1) {
                fprintf(stderr, "\nError: the encryption failed during reimport\n");
                if(g_continue_anyway) { ret_value = -1; goto quit; }
                myexit(QUICKBMS_ERROR_ENCRYPTION);
            }

            // yes, size and old_zsize because it's the opposite of the extraction
            if(size > old_zsize) {
                // first try zopfli which is a bit faster and grants better results in some situations
                if((new_compression_type == COMP_ZLIB_COMPRESS) || (new_compression_type == COMP_DEFLATE_COMPRESS)) {
                    if(new_compression_type == COMP_ZLIB_COMPRESS)          g_compression_type = COMP_ZOPFLI_ZLIB_COMPRESS;
                    else                                                    g_compression_type = COMP_ZOPFLI_DEFLATE_COMPRESS;
                    fprintf(stderr, "- compressed size too big, I try using the zopfli method (may be slow)\n");
                    myfseek(fdnum, oldoff, SEEK_SET);
                    xsize = backup_xsize;
                    zsize = backup_zsize;
                    size  = backup_size;
                    goto redo_import;
                }
                // the last chance is uberflate
                if((new_compression_type == COMP_ZOPFLI_ZLIB_COMPRESS) || (new_compression_type == COMP_ZOPFLI_DEFLATE_COMPRESS)) {
                    if(new_compression_type == COMP_ZOPFLI_ZLIB_COMPRESS)   g_compression_type = COMP_KZIP_ZLIB_COMPRESS;
                    else                                                    g_compression_type = COMP_KZIP_DEFLATE_COMPRESS;
                    fprintf(stderr, "- compressed size too big, I try using the uberflate/kzip method (may be very slow!)\n");
                    myfseek(fdnum, oldoff, SEEK_SET);
                    xsize = backup_xsize;
                    zsize = backup_zsize;
                    size  = backup_size;
                    goto redo_import;
                }

                ask_force_reimport(0,
                    old_zsize = size;
                )
            }
            // separated to allow the "force" writing
            if(size <= old_zsize) {
                len = myfw(fdnum, out, size);
                if(len != size) {
                    fprintf(stderr, "\n"
                        "Error: impossible to write 0x%"PRIx" bytes (total 0x%"PRIx")\n"
                        "       Check your disk space\n",
                        (len < 0) ? size : (size - len), size);
                    if(g_continue_anyway) { ret_value = -1; goto quit; }
                    myexit(QUICKBMS_ERROR_FILE_WRITE);
                }
                if(!g_quiet) printf("< %"PRIx" %-10"PRIu" %s\n", offset, size, fname);
                g_reimported_files++;

                /* not needed at the moment, maybe in future but keep in mind the notes in quickbms.txt!
                myfseek(fdnum, reimport_zsize_offset, SEEK_SET);
                fputxx(fdnum, size, 4);     // zsize->size must be swapped!
                myfseek(fdnum, reimport_size_offset, SEEK_SET);
                fputxx(fdnum, zsize, 4);    // zsize->size must be swapped!
                */
            }

skip_import:
            myfseek(fdnum, oldoff, SEEK_SET);
        } else {
            static int  reimport_skip_progress_idx = 0;
            static char reimport_skip_progress[] = "|/-\\|/-\\";
            if(!reimport_skip_progress[reimport_skip_progress_idx]) reimport_skip_progress_idx = 0;
            fputc(reimport_skip_progress[reimport_skip_progress_idx], stderr);
            fputc('\r', stderr);
            reimport_skip_progress_idx++;
        }

    } else if(memfile && !size && !zsize && !fdnum) {
        // memory file initialization: log MEMORY_FILE 0 0
        dumpa_memory_file(memfile, &out, size, &outsize);
        goto quit;

    } else {
        if((!g_void_dump && !non_files) || (g_void_dump && filetmp)) {
            if(g_list_only || g_force_output || g_quickiso || g_quickzip) {
            } else {
                // the following is not so good for fname ""
                // because will ask the confirmation twice in some occasions
                // Fixed: last_name_crc does the job
                fname = create_dir(fname, 1, 0, 0, 1);
                dumpa_name_overwrite_check
            }
        }

        oldoff = myftell(fdnum);
        myfseek(fdnum, offset, SEEK_SET);
        dumpa_state(&quickbms_compression, &quickbms_encryption, zsize, size, xsize);

        // direct_copy saves memory with normal files
        if(!non_files && !quickbms_encryption && !quickbms_compression && !g_quickzip) {
            #ifdef ENABLE_DIRECT_COPY
            direct_copy = 1;
            #endif

            // find a way to "guess" if input and output are the same file:
            // it must be simple, cross-platform and doesn't matter if it's not "perfect"
            // because the difference is just in copying the file chunk-by-chunk or all-in-one
            // without negative effects in case of false positives and errors (same input and
            // output is usually wrong but it's valid for compression and encryption that are
            // not involved here).
            // Note that Windows has various API to get the exact path of an HANDLE (take a look
            // at offbreak) but I prefer to use this work-around at the moment.
            u8 *name1 = get_filename(fname);
            u8 *name2 = g_filenumber[fdnum].filename;
            if(name1 && name2 && !stricmp(name1, name2)) {
                fd = xfopen(fname, "rb");
                if(fd) {
                    // very easy, on Windows we have st_ino, st_mode, st_size and all the *time
                    struct stat xstat1, xstat2;
                    memset(&xstat1, 0, sizeof(xstat1));
                    fstat(fileno(g_filenumber[fdnum].fd), &xstat1);
                    memset(&xstat2, 0, sizeof(xstat2));
                    fstat(fileno(fd), &xstat2);
                    if(!memcmp(&xstat1, &xstat2, sizeof(xstat1))) {
                        direct_copy = 0;
                    }
                    FCLOSE(fd);
                }
            }

            // input non-files
            // it's better to avoid the direct_cop optimization
            // with these alternative files
            if(
                g_filenumber[fdnum].sd || // sockets
                g_filenumber[fdnum].pd || 
                g_filenumber[fdnum].ad ||
                g_filenumber[fdnum].vd ||
                g_filenumber[fdnum].md
            ) {
                direct_copy = 0;
            }
        }

        if(!direct_copy) {
            //if(size == -1) ALLOC_ERR;
            myalloc(&out, size, &outsize);      // + 1 is NOT necessary
            if(quickbms_compression) { // remember that the (size == zsize) check is NOT valid so can't be used in a "generic" way!
                //if(xsize == -1) ALLOC_ERR;
                //if(zsize == -1) ALLOC_ERR;
                len = dumpa_xsize(zsize, xsize);
                myalloc(&in, len, &insize);   // + 1 is NOT necessary
                len = myfr(fdnum, in, len, TRUE);
                if(len < 0) { ret_value = -1; goto quit; }
                len = perform_encryption(in, len);
                if(len == -1) {
                    fprintf(stderr, "\nError: the encryption failed\n");
                    if(g_continue_anyway) { ret_value = -1; goto quit; }
                    myexit(QUICKBMS_ERROR_ENCRYPTION);
                }
                // zsize value will not be touched or xsize is totally useless
                if(len < zsize) zsize = len;

                size = perform_compression(in, zsize, &out, size, &outsize, offset);

                if(g_comtype_scan && (size <= 0)) {  // both invalid and empty
                    myfseek(fdnum, oldoff, SEEK_SET);   // important, NEVER forget it!
                    goto quit;
                }
                if(size < 0) {
                    fprintf(stderr, "\n"
                        "Error: there is an error with the decompression\n"
                        "       the returned output size is negative (%"PRId")\n", size);
                    if(g_continue_anyway) { ret_value = -1; goto quit; }
                    myexit(QUICKBMS_ERROR_COMPRESSION);
                }
                // size/outsize limit check done directly in perform_compression
                // do NOT add checks which verify if the unpacked size is like the expected one, I prefer the compatibility
            } else {
                len = dumpa_xsize(size, xsize);
                len = myfr(fdnum, out, len, TRUE);
                if(len < 0) { ret_value = -1; goto quit; }
                len = perform_encryption(out, len);
                if(len == -1) {
                    fprintf(stderr, "\nError: the encryption failed\n");
                    if(g_continue_anyway) { ret_value = -1; goto quit; }
                    myexit(QUICKBMS_ERROR_ENCRYPTION);
                }
                // size value will not be touched or xsize is totally useless
                if(len < size) size = len;
            }
        }

        len = size;
        if(sockfile) {
            len = socket_write(sockfile, out, size);

        } else if(procfile) {
            len = process_write(procfile, out, size);

        } else if(audiofile) {
            len = audio_write(audiofile, out, size);

        } else if(videofile) {
            len = video_write(videofile, out, size);

        } else if(winmsgfile) {
            len = winmsg_write(winmsgfile, out, size);

        } else if(memfile) {
            len = dumpa_memory_file(memfile, &out, size, &outsize);

        } else if(!g_void_dump || (g_void_dump && filetmp)) {

            if(g_force_output) {
                if(!strcmp(g_force_output, "-")) {
                    #ifdef WIN32
                    #define STDOUT_FILENAME "CON"
                    #else
                    #define STDOUT_FILENAME "/dev/tty"
                    #endif

                    // just an experimental and maybe useless thing because doesn't seem to redirect output
                    //freopen(STDOUT_FILENAME, "wb", stdout); fd = stdout;
                    fd = fopen(STDOUT_FILENAME, "wb");
                    if(!fd) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
                    #ifdef O_BINARY
                    setmode(fileno(fd), O_BINARY);
                    #endif
                } else {
                    fd = xfopen(g_force_output, "ab");  // better than "wb" ?
                    if(!fd) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
                }
                //fname = g_force_output;
            } else {
                if(nametmp) {    // the length of the extension is fixed in the database
                    idx = get_var_from_name("QUICKBMS_FILENAME", -1);
                    if(idx >= 0) {
                        xname = get_var(idx);
                        if(!xname || !xname[0]) {
                            idx = -1;
                        } else {
                            fname = xname;
                            fname = clean_filename(fname, NULL);
                            fname = create_dir(fname, 1, 0, 0, 1);
                            dumpa_name_overwrite_check
                        }
                    }

                    if(idx < 0) {
                        if(direct_copy) {       // unfortunately will not catch the tga files in this way, that's the only price
                            len = size;         // but note that not all the tga files use the TRUEVISION-XFILE ending!
                            if(len > sizeof(tmpbuff)) len = sizeof(tmpbuff);
                            len = myfr(fdnum, tmpbuff, len, TRUE);
                            if(len < 0) { ret_value = -1; goto quit; }
                            myfseek(fdnum, offset, SEEK_SET);
                            ext = sign_ext(tmpbuff, len);
                        } else {
                            ext = sign_ext(out, size);
                        }
                        if(tmp_ext) ext = tmp_ext;
                        strcpy(strrchr(fname, '.') + 1, ext);
                        dumpa_name_overwrite_check
                        // check_overwrite is used before processing the file for performance reasons
                        // because would be useless to extract a 2gb file that is already extracted
                        // that's why this function is not called below but only here and in the main
                        // part of the function above
                    }
                }
                for(;;) {
                    quickbms_archive_output_write(iso, NULL)
                    quickbms_archive_output_write(zip, out)

                         if(g_append_mode == APPEND_MODE_APPEND)    { fd = xfopen(fname, "r+b"); if(!fd) fd = xfopen(fname, "wb"); }    // append
                    else if(g_append_mode == APPEND_MODE_OVERWRITE) { fd = xfopen(fname, "r+b"); if(!fd) fd = xfopen(fname, "wb"); }    // overwrite
                    else if(g_append_mode == APPEND_MODE_BEFORE)    { fd = xfopen(fname, "r+b"); if(!fd) fd = xfopen(fname, "wb"); }    // before
                    else                                            {                                    fd = xfopen(fname, "wb"); }
                    //if(!fd) STD_ERR(QUICKBMS_ERROR_FILE_WRITE);
                    if(fd) break;
                    fname = rename_invalid(fname);
                }
                if(g_append_mode == APPEND_MODE_APPEND) {   // use "r+b" instead of "ab" to have information about the real offset
                    fseek(fd, 0, SEEK_END);
                }
            }

            if(g_append_mode == APPEND_MODE_BEFORE) {
                make_file_space(fd, size);
            }

            append_mode_extracted_file(
                {
                    ef->offset = ftell(fd);
                }
            )

            if(fd) {
                len = dumpa_direct_copy(
                    fdnum, fd,
                    direct_copy ? NULL : out,
                    size,
                    0, fname);
            }

            if(g_quickiso) {
                quickiso_padding(g_quickiso);
                fd = NULL;
            }
            if(g_quickzip) {
                fd = NULL;
            }
            FCLOSE(fd);

            quickbms_execute_pipe(g_quickbms_execute_file, NULL, 0, NULL, 0, fname);
        }
        if(len != size) {
            fprintf(stderr, "\n"
                "Error: impossible to write 0x%"PRIx" bytes (total 0x%"PRIx")\n"
                "       Check your disk space\n",
                (len < 0) ? size : (size - len), size);
            if(g_continue_anyway) { ret_value = -1; goto quit; }
            myexit(QUICKBMS_ERROR_FILE_WRITE);
        }

        myfseek(fdnum, oldoff, SEEK_SET);
    }
    if(!memfile) {
        g_extracted_files++;
        if(g_mex_default) {
            add_var(EXTRCNT_idx, NULL, NULL, g_extracted_files, sizeof(int));
        }
    }
quit:
    return(ret_value);
}



u8 *fgetss(int fdnum, int chr, int unicode, int line) {  // reads a chr terminated string, at the moment unicode is referred to the 16bit unicode
    static int  buffsz  = 0;
    static u8   *buff   = NULL;
    int     i,
            len,
            c,
            unicnt  = 0,
            except  = 0;
    wchar_t wc;
    u8      tmp[32];

    if(chr < 0) {
        chr = -chr;
        except = 1;
    }
    // if(!fd) do nothing, modify myfgetc
    for(i = 0;;) {

        //c = myfgetc(fdnum);
        if(myfr(fdnum, tmp, 1, line ? FALSE : TRUE) <= 0) {
            c = -1;
        } else {
            c = tmp[0];
        }

        if(c < 0) {
            if(!i) return NULL;    // return a NULL if EOF... this is for compatibility with old versions of quickbms although it's not so right
            break;
        }

        // use c if len is 1 or tmp if it's longer
        len = 1;
        if(unicode) {

            // shared with CMD_Set_func
            if(!unicnt) wc = 0;

            if(g_endian == MYLITTLE_ENDIAN) {
                if(unicnt) wc |= (c << 8);
                else       wc |= c;
            } else {
                if(unicnt) wc |= c;
                else       wc |= (c << 8);
            }
            unicnt++;
            if(unicnt < 2) continue;
            unicnt = 0;

            len = utf16_to_utf8_chr(wc, tmp, sizeof(tmp), 0, g_codepage);

            if(len == 1) c = tmp[0];
            else         c = -1; // to bypass "except"
        }

        if(line && !i) {
            //if(!c || strchr(" \t\r\n", c)) continue;
            if(strchr(" \t", c)) continue;
        }
        if(except) {
            if(c != chr) break;
        } else {
            if(line && !c) break;   // don't add '\r', I want a fgets-like solution
            if(c == chr) break;
        }

        if((i + len) >= buffsz) {
            //if((buffsz + len + STRINGSZ + 1) < buffsz) ALLOC_ERR;
            buffsz += len + STRINGSZ;
            buff = realloc(buff, buffsz + 1);
            if(!buff) STD_ERR(QUICKBMS_ERROR_MEMORY);
        }
        if(len == 1) {  // use c
            buff[i] = c;
        } else {        // use tmp
            memcpy(buff + i, tmp, len);
        }
        i += len;
    }
    //if(c < 0) return NULL;
    if(!buff) buff = malloc(1); // remember, anything returned by this function MUST be allocated
    buff[i] = 0;
    if(except) {
        if(c < 0) {
        } else {
            if(unicode) myfseek(fdnum, -2, SEEK_CUR);
            else        myfseek(fdnum, -1, SEEK_CUR);
        }
    }
    if(line) {
        for(i = strlen(buff) - 1; i >= 0; i--) {  // buff has been nulled
            if(!strchr(" \t\r\n", buff[i])) break;
            buff[i] = 0;
        }
    }
    return buff;
}



int fputss(int fdnum, u8 *data, int chr, int unicode, int line, int maxsz) {  // writes a chr terminated string, currently unicode is referred to utf16
    int     i,
            c,
            t;
    wchar_t wc;

    if(!data) data = "";
    if(maxsz < 0) maxsz = strlen(data) + 1;
    // if(!fd) do nothing, modify myfputc
    for(i = 0;;) {
        if((maxsz >= 0) && (i >= maxsz)) break;

        if(unicode) {
            t = utf8_to_utf16_chr(data + i, maxsz - i, &wc, 0, g_codepage);
            if(t <= 0) break;
            i += t;
            c = wc;
        } else {
            c = data[i++];
        }

        if(line) {
            if(c == 0x00) break;
            if(c == '\r') break;
            if(c == '\n') break;
        }
        if((chr < 0) && (c == 0x00)) break;
        if(unicode) c = fputxx(fdnum, c, 2);
        else        c = myfputc(c, fdnum);
        if(c < 0) return -1;
        if(c == chr) break;
    }
    if(line) {
        if(myfputc('\r', fdnum) < 0) return -1;
        if(myfputc('\n', fdnum) < 0) return -1;
    }
    return i;
}



#include "types.c"



u8 *myfrx(int fdnum, int type, int *ret_num, int *error) {
    long double tmp_longdouble;
    double  tmp_double;
    float   tmp_float;
    u64     tmp64;
    int     retn    = 0,
            i,
            t,
            mask,
            tmp_error,
            tmp_ret_num;
    u8      tmp[64],
            c,
            *ret    = NULL;

    if(!ret_num) ret_num = &tmp_ret_num;
    if(!error) error = &tmp_error;
    *error = 0;
    switch(type) {
        case BMS_TYPE_LONGLONG:     retn = fgetxx(fdnum, 8, error);     break;
        case BMS_TYPE_LONG:         retn = fgetxx(fdnum, 4, error);     break;
        case BMS_TYPE_SHORT:        retn = fgetxx(fdnum, 2, error);     break;
        case BMS_TYPE_BYTE:         retn = fgetxx(fdnum, 1, error);     break;
        case BMS_TYPE_THREEBYTE:    retn = fgetxx(fdnum, 3, error);     break;
        case BMS_TYPE_ASIZE:        retn = myfilesize(fdnum);           break;
        case BMS_TYPE_STRING: {
            ret  = fgetss(fdnum, 0,    0, 0);
            if(!ret) *error = 1;    // this damn error stuff is needed for compatibility with the old quickbms
            break;                  // and located here doesn't affect the performances
        }
        case BMS_TYPE_LINE: {
            ret  = fgetss(fdnum, '\n', 0, 1);
            if(!ret) *error = 1;
            delimit(ret);
            break;
        }
        case BMS_TYPE_FILENAME: {
            CHECK_FILENUM
            ret  = g_filenumber[fdnum].filename;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_BASENAME: {
            CHECK_FILENUM
            ret  = g_filenumber[fdnum].basename;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_FILEPATH: {
            CHECK_FILENUM
            ret  = g_filenumber[fdnum].filepath;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_FULLNAME: {
            CHECK_FILENUM
            ret  = g_filenumber[fdnum].fullname;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_FULLBASENAME: {
            CHECK_FILENUM
            ret  = g_filenumber[fdnum].fullbasename;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_EXTENSION: {
            CHECK_FILENUM
            ret  = g_filenumber[fdnum].fileext;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_CURRENT_FOLDER: {
            ret  = g_current_folder;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_FILE_FOLDER: {
            ret  = g_file_folder;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_INOUT_FOLDER: {
            ret  = g_output_folder;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_BMS_FOLDER: {
            ret  = g_bms_folder;
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_UNICODE: {
            ret  = fgetss(fdnum, 0,    1, 0);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_FLOAT: {
            // use fgetxx instead of myfr for handling the endianess
            retn = fgetxx(fdnum, 4, error);
            if(*error) break;
            //tmp_float = *(float *)((void *)(&retn));
            tmp_float = 0;
            memcpy(&tmp_float, &retn, 4);
            retn = (int)tmp_float;
            break;
        }
        case BMS_TYPE_DOUBLE: {
            // use fgetxx instead of myfr for handling the endianess
            tmp64 = fgetxx(fdnum, 8, error);
            if(*error) break;
            //tmp_double = *(double *)((void *)(&tmp64));
            tmp_double = 0;
            memcpy(&tmp_double, &tmp64, 8);
            retn = (int)tmp_double;
            break;
        }
        case BMS_TYPE_LONGDOUBLE: {
            //myfr(fdnum, tmp, 12, TRUE); // I want to handle also the endianess
            memset(tmp, 0, sizeof(tmp));
            for(c = 0; c < 12; c++) {
                if(g_endian == MYLITTLE_ENDIAN) {
                    t = myfr(fdnum, tmp + c, 1, TRUE);
                } else {
                    t = myfr(fdnum, tmp + 11 - c, 1, TRUE);
                }
                if(t < 0) break;
            }
            //tmp_longdouble = *(long double *)tmp;
            tmp_longdouble = 0;
            memcpy(&tmp_longdouble, tmp, sizeof(tmp_longdouble));
            retn = (int)tmp_longdouble;
            break;
        }
        case BMS_TYPE_VARIABLE: {
            do {
                c = fgetxx(fdnum, 1, error);
                if(*error) break;
                retn = (retn << 7) | (c & 0x7f);
            } while(c & 0x80);
            break;
        }
        case BMS_TYPE_VARIABLE2: {
            retn = unreal_index(fdnum);
            break;
        }
        case BMS_TYPE_VARIABLE3: {
            i = 0;
            do {
                c = fgetxx(fdnum, 1, error);
                if(*error) break;
                retn += ((c & 0x7f) << i);
                i += 7;
            } while(!(c & 0x80));
            break;
        }
        case BMS_TYPE_VARIABLE4: {
            i = 0;
            do {
                c = fgetxx(fdnum, 1, error);
                if(*error) break;
                retn |= ((c & 0x7f) << i);
                i += 7;
            } while(c & 0x80);
            break;
        }
        case BMS_TYPE_VARIABLE5: {
            c = fgetxx(fdnum, 1, error);
            if(*error) break;
            mask = 0x80;
            for(i = 0; mask; i++) {
                if((c & mask) == 0) {
                    retn += ((u64)(c & (mask - 1)) << (u64)(i * 8));
                    break;
                }
                retn |= ((u64)fgetxx(fdnum, 1, error) << (u64)(i * 8));
                if(*error) break;
                mask >>= 1;
            }
            break;
        }
        case BMS_TYPE_VARIANT: {
            retn = fgetxx(fdnum, 2, error);
            if(*error) break;
            memset(tmp, 0, sizeof(tmp));
            t = myfr(fdnum, tmp, 6, TRUE);
            //if(t < 0) ??? do nothing because it's not even considered
            switch(retn) {
                case 0:  type = BMS_TYPE_NONE;      break;
                case 1:  type = BMS_TYPE_NONE;      break;
                case 2:  type = BMS_TYPE_SHORT;     break;
                case 3:  type = BMS_TYPE_LONG;      break;
                case 4:  type = BMS_TYPE_FLOAT;     break;  // float
                case 5:  type = BMS_TYPE_DOUBLE;    break;  // double
                case 6:  type = BMS_TYPE_LONGLONG;  break;
                case 7:  type = BMS_TYPE_LONGLONG;  break;
                case 8:  type = BMS_TYPE_UNICODE;   break;
                case 9:  type = BMS_TYPE_LONG;      break;
                case 10: type = BMS_TYPE_LONG;      break;
                case 11: type = BMS_TYPE_SHORT;     break;
                case 12: type = BMS_TYPE_VARIANT;   break;
                case 17: type = BMS_TYPE_BYTE;      break;
                default: type = BMS_TYPE_LONG;      break;  // ???
            }
            return(myfrx(fdnum, type, ret_num, error));
            break;
        }
        case BMS_TYPE_NONE: retn = 0;   break;
        case BMS_TYPE_TIME: {
            ret = time_to_strtime(fdnum);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_TIME64: {
            ret = time64_to_strtime(fdnum);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_CLSID: {
            ret = bytes2clsid(fdnum);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_IPV4: {
            retn = fgetxx(fdnum, 4, error);
            if(*error) break;
            if(g_endian != MYLITTLE_ENDIAN) retn = swap32(retn);  // because ip2str works in big endian
            ret = ip2str(retn);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_IPV6: {
            ret = ipv6_to_string(fdnum);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_ASM: {
            ret = quickbms_disasm(fdnum);
            if(!ret) *error = 1;
            break;
        }
        case BMS_TYPE_SIGNED_BYTE:         retn = fgetxx(fdnum, 1, error); if(retn & 0x80)       retn |= -0x100LL;         break;
        case BMS_TYPE_SIGNED_SHORT:        retn = fgetxx(fdnum, 2, error); if(retn & 0x8000)     retn |= -0x10000LL;       break;
        case BMS_TYPE_SIGNED_THREEBYTE:    retn = fgetxx(fdnum, 3, error); if(retn & 0x800000)   retn |= -0x1000000LL;     break;
        case BMS_TYPE_SIGNED_LONG:         retn = fgetxx(fdnum, 4, error); if(retn & 0x80000000) retn |= -0x100000000LL;   break;
        default: {
            fprintf(stderr, "\nError: invalid datatype %d\n", (i32)type);
            myexit(QUICKBMS_ERROR_BMS);
            break;
        }
    }
    *ret_num = retn;
    //if(!ISNUMTYPE(type) && !ret) *error = 1;  // bad, decrease a lot the performances
    return ret;
}



int myfwx(int fdnum, int varn, int type) {
    long double tmp_longdouble;
    double  tmp_double;
    float   tmp_float;
    u64     tmp64;
    u32     tmp32;
    int     retn    = 0;
    u8      tmp[64],
            c;

    switch(type) {
        case BMS_TYPE_LONGLONG:     retn = fputxx(fdnum, get_var32(varn), 8);   break;
        case BMS_TYPE_SIGNED_LONG:
        case BMS_TYPE_LONG:         retn = fputxx(fdnum, get_var32(varn), 4);   break;
        case BMS_TYPE_SIGNED_SHORT:
        case BMS_TYPE_SHORT:        retn = fputxx(fdnum, get_var32(varn), 2);   break;
        case BMS_TYPE_SIGNED_BYTE:
        case BMS_TYPE_BYTE:         retn = fputxx(fdnum, get_var32(varn), 1);   break;
        case BMS_TYPE_SIGNED_THREEBYTE:
        case BMS_TYPE_THREEBYTE:    retn = fputxx(fdnum, get_var32(varn), 3);   break;
        case BMS_TYPE_ASIZE:        retn = fputxx(fdnum, myfilesize(fdnum), 4); break;
        case BMS_TYPE_STRING: { // NULL delimited string
            retn = fputss(fdnum, get_var(varn), 0, 0, 0, -1 /*get_varsz(varn)*/);
            break;
        }
        case BMS_TYPE_LINE: {
            retn = fputss(fdnum, get_var(varn), -1, 0, 1, -1 /*get_varsz(varn)*/);
            break;
        }
        case BMS_TYPE_FILENAME: {
            CHECK_FILENUM
            retn = fputss(fdnum, g_filenumber[fdnum].filename, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_BASENAME: {
            CHECK_FILENUM
            retn = fputss(fdnum, g_filenumber[fdnum].basename, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_FILEPATH: {
            CHECK_FILENUM
            retn = fputss(fdnum, g_filenumber[fdnum].filepath, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_FULLNAME: {
            CHECK_FILENUM
            retn = fputss(fdnum, g_filenumber[fdnum].fullname, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_FULLBASENAME: {
            CHECK_FILENUM
            retn = fputss(fdnum, g_filenumber[fdnum].fullbasename, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_EXTENSION: {
            CHECK_FILENUM
            retn = fputss(fdnum, g_filenumber[fdnum].fileext, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_CURRENT_FOLDER: {
            retn = fputss(fdnum, g_current_folder, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_FILE_FOLDER: {
            retn = fputss(fdnum, g_file_folder, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_INOUT_FOLDER: {
            retn = fputss(fdnum, g_output_folder, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_BMS_FOLDER: {
            retn = fputss(fdnum, g_bms_folder, -1, 0, 0, -1);
            break;
        }
        case BMS_TYPE_UNICODE: {    // NULL delimited
            retn = fputss(fdnum, get_var(varn), 0, 1, 0, -1);
            break;
        }
        case BMS_TYPE_FLOAT: {
            retn = get_var32(varn);
            tmp_float = (float)retn;
            //retn = *(int *)((void *)(&tmp_float));
            retn = 0;
            memcpy(&retn, &tmp_float, 4);
            retn = fputxx(fdnum, retn, 4);
            break;
        }
        case BMS_TYPE_DOUBLE: {
            retn = get_var32(varn);
            tmp_double = (double)retn;
            //tmp64 = *(u64 *)((void *)(&tmp_double));
            tmp64 = 0;
            memcpy(&tmp64, &tmp_double, 8);
            // fputxx is 32bit on !QUICKBMS64
            if(g_endian == MYLITTLE_ENDIAN)  {
                retn = fputxx(fdnum, tmp64, 4);
                retn = fputxx(fdnum, tmp64 >> 32, 4);
            } else {
                retn = fputxx(fdnum, tmp64 >> 32, 4);
                retn = fputxx(fdnum, tmp64, 4);
            }
            break;
        }
        case BMS_TYPE_LONGDOUBLE: {
            retn = get_var32(varn);
            tmp_longdouble = (long double)retn;
            memcpy(tmp, (void *)&tmp_longdouble, sizeof(tmp_longdouble));
            for(c = 0; c < 12; c++) {
                if(g_endian == MYLITTLE_ENDIAN) {
                    myfw(fdnum, tmp + c, 1);
                } else {
                    myfw(fdnum, tmp + 11 - c, 1);
                }
            }
            retn = 0;
            break;
        }
        case BMS_TYPE_VARIABLE:     retn = put_type_variable(fdnum, get_var32(varn));   break;
        case BMS_TYPE_VARIABLE2: {
            c = make_unreal_index(get_var32(varn), tmp);
            retn = myfw(fdnum, tmp, c);
            break;
        }
        case BMS_TYPE_VARIABLE3:    retn = put_type_variable3(fdnum, get_var32(varn));  break;
        case BMS_TYPE_VARIABLE4:    retn = put_type_variable4(fdnum, get_var32(varn));  break;
        case BMS_TYPE_VARIABLE5:    retn = put_type_variable5(fdnum, get_var32(varn));  break;
        //case BMS_TYPE_VARIANT:    // unsupported
        case BMS_TYPE_NONE: retn = 0;   break;
        case BMS_TYPE_TIME: {
            strtime_to_time(get_var(varn), &tmp32, NULL);
            retn = fputxx(fdnum, tmp32, 4);
            break;
        }
        case BMS_TYPE_TIME64: {
            strtime_to_time(get_var(varn), NULL, &tmp64);
            // fputxx is 32bit on !QUICKBMS64
            if(g_endian == MYLITTLE_ENDIAN)  {
                retn = fputxx(fdnum, tmp64, 4);
                retn = fputxx(fdnum, tmp64 >> 32, 4);
            } else {
                retn = fputxx(fdnum, tmp64 >> 32, 4);
                retn = fputxx(fdnum, tmp64, 4);
            }
            break;
        }
        case BMS_TYPE_CLSID: {
            retn = clsid2bytes(fdnum, get_var(varn));
            break;
        }
        case BMS_TYPE_IPV4: {
            retn = str2ip(get_var(varn));
            if(g_endian != MYLITTLE_ENDIAN) retn = swap32(retn);  // because str2ip works in big endian
            retn = fputxx(fdnum, retn, 4);
            break;
        }
        case BMS_TYPE_IPV6: {
            retn = string_to_ipv6(fdnum, get_var(varn));
            break;
        }
        case BMS_TYPE_ASM: {
            retn = quickbms_asm(fdnum, get_var(varn));
            break;
        }
        default: {
            fprintf(stderr, "\nError: invalid or unsupported datatype %d\n", (i32)type);
            myexit(QUICKBMS_ERROR_BMS);
            break;
        }
    }
    return(retn);
}


