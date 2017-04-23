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

// QuickBMS variables-related operations



/*
TODO and notes
var.size referred to var.name must be ever >= VAR_NAMESZ, this is an old
work-around introduced when I opted for strings allocated with a minimum
size of STRINGSZ.

check script:
    get VAR long
    print "%VAR%"
    set VAR2 string VAR
    print "%VAR2%"
*/



void check_variable_errors(int idx, variable_t *myvar) {
    variable_t  *var;

    if(myvar) var = myvar;
    else      var = &g_variable[idx];

    if(var->name) {
        if(
#ifdef QUICKBMS_VAR_STATIC
            (var->name  != var->name_static) &&
#endif
            (var->name  != var->name_alloc)) {
            fprintf(stderr, "\nError: %svariable %"PRId" contains an invalid name pointer, contact me!\n", (var == myvar) ? "array " : "", idx);
            myexit(QUICKBMS_ERROR_BMS);
        }
    }
    if(var->value) {
        if(
#ifdef QUICKBMS_VAR_STATIC
            (var->value != var->value_static) &&
#endif
            (var->value != var->value_alloc)) {
            fprintf(stderr, "\nError: %svariable %"PRId" contains an invalid value pointer, contact me!\n", (var == myvar) ? "array " : "", idx);
            myexit(QUICKBMS_ERROR_BMS);
        }
    }
}



int get_memory_file(u8 *str) {
    int     ret = 0;    // because -1 is returned for MEMORY_FILE

    // MEMORY_FILE  = -1
    // MEMORY_FILE1 = -1
    // MEMORY_FILE2 = -2

    if(str) {
        ret = myatoi(str + MEMORY_FNAMESZ);
        if(!ret) ret++;
        if((ret < 0) || (ret > MAX_FILES)) {
            fprintf(stderr, "\nError: too big MEMORY_FILE number\n");
            myexit(QUICKBMS_ERROR_BMS);
        }
        ret = -ret;
    }
    if((ret >= 0) || (-ret < 0)) {  // 0x80000000
        fprintf(stderr, "\nError: the memory file has a positive number\n");
        myexit(QUICKBMS_ERROR_BMS);
    }
    return ret;
}



int add_datatype(u8 *str) {
    if(str) {
        if(!stricmp(str, "Long"))           return BMS_TYPE_LONG;
        if(!stricmp(str, "Int"))            return BMS_TYPE_SHORT;
        if(!stricmp(str, "Byte"))           return BMS_TYPE_BYTE;
        if(!stricmp(str, "ThreeByte"))      return BMS_TYPE_THREEBYTE;
        if(!stricmp(str, "String"))         return BMS_TYPE_STRING;
        if(!stricmp(str, "ASize"))          return BMS_TYPE_ASIZE;
        // added by me
        if(!stricmp(str, "sLong"))          return BMS_TYPE_SIGNED_LONG;
        if(!stricmp(str, "sInt"))           return BMS_TYPE_SIGNED_SHORT;
        if(!stricmp(str, "sShort"))         return BMS_TYPE_SIGNED_SHORT;
        if(!stricmp(str, "sByte"))          return BMS_TYPE_SIGNED_BYTE;
        if(!stricmp(str, "sThreeByte"))     return BMS_TYPE_SIGNED_THREEBYTE;
        if(!stricmp(str, "signed_Long"))    return BMS_TYPE_SIGNED_LONG;
        if(!stricmp(str, "signed_Int"))     return BMS_TYPE_SIGNED_SHORT;
        if(!stricmp(str, "signed_Short"))   return BMS_TYPE_SIGNED_SHORT;
        if(!stricmp(str, "signed_Byte"))    return BMS_TYPE_SIGNED_BYTE;
        if(!stricmp(str, "signed_ThreeByte"))   return BMS_TYPE_SIGNED_THREEBYTE;
        if(stristr(str,  "bits"))           return BMS_TYPE_BITS;
        if(!stricmp(str, "Longlong"))       return BMS_TYPE_LONGLONG;
        //if(!stricmp(str, "Llong"))          return BMS_TYPE_LONGLONG;
        if(!stricmp(str, "Short"))          return BMS_TYPE_SHORT;
        if(!stricmp(str, "Char"))           return BMS_TYPE_BYTE;
        if(!stricmp(str, "dword"))          return BMS_TYPE_LONG;
        if(!stricmp(str, "word"))           return BMS_TYPE_SHORT;
        if(!stricmp(str, "char16"))         return BMS_TYPE_SHORT;
        if(!stricmp(str, "FileName"))       return BMS_TYPE_FILENAME;
        if(!stricmp(str, "BaseName"))       return BMS_TYPE_BASENAME;
        if(!stricmp(str, "FilePath"))       return BMS_TYPE_FILEPATH;
        if(!stricmp(str, "FullPath"))       return BMS_TYPE_FILEPATH;
        if(!stricmp(str, "FullName"))       return BMS_TYPE_FULLNAME;
        if(!stricmp(str, "Extension"))      return BMS_TYPE_EXTENSION;
        if(!stricmp(str, "FileExt"))        return BMS_TYPE_EXTENSION;
        if(!stricmp(str, "current_folder")) return BMS_TYPE_CURRENT_FOLDER;
        if(!stricmp(str, "file_folder"))    return BMS_TYPE_FILE_FOLDER;
        if(!stricmp(str, "input_folder"))   return BMS_TYPE_INOUT_FOLDER;
        if(!stricmp(str, "output_folder"))  return BMS_TYPE_INOUT_FOLDER;
        if(!stricmp(str, "bms_folder"))     return BMS_TYPE_BMS_FOLDER;
        if(!stricmp(str, "Unicode"))        return BMS_TYPE_UNICODE;
        if(!stricmp(str, "UTF-16"))         return BMS_TYPE_UNICODE;
        if(!stricmp(str, "UTF16"))          return BMS_TYPE_UNICODE;
        if(!stricmp(str, "TO_Unicode"))     return BMS_TYPE_TO_UNICODE;
        if(!stricmp(str, "TO_UTF-16"))      return BMS_TYPE_TO_UNICODE;
        if(!stricmp(str, "TO_UTF16"))       return BMS_TYPE_TO_UNICODE;
        if(!stricmp(str, "Binary"))         return BMS_TYPE_BINARY;
        if(!stricmp(str, "Line"))           return BMS_TYPE_LINE;
        if(!stricmp(str, "UTF-8"))          return BMS_TYPE_STRING;
        if(!stricmp(str, "UTF8"))           return BMS_TYPE_STRING;
        if(!stricmp(str, "Alloc"))          return BMS_TYPE_ALLOC;
        if(!stricmp(str, "Compressed"))     return BMS_TYPE_COMPRESSED;
        if(!stricmp(str, "float"))          return BMS_TYPE_FLOAT;
        if(!stricmp(str, "float32"))        return BMS_TYPE_FLOAT;
        if(!stricmp(str, "double"))         return BMS_TYPE_DOUBLE;
        if(!stricmp(str, "float64"))        return BMS_TYPE_DOUBLE;
        if(!stricmp(str, "double64"))       return BMS_TYPE_DOUBLE;
        if(!stricmp(str, "longdouble"))     return BMS_TYPE_LONGDOUBLE;
        if(!stricmp(str, "double96"))       return BMS_TYPE_LONGDOUBLE;
        if(!stricmp(str, "bool"))           return BMS_TYPE_LONG;
        if(!stricmp(str, "void"))           return BMS_TYPE_LONG;
        if(!stricmp(str, "variable"))       return BMS_TYPE_VARIABLE;
        if(!stricmp(str, "variable1"))      return BMS_TYPE_VARIABLE;
        if(!stricmp(str, "variable2"))      return BMS_TYPE_VARIABLE2;
        if(!stricmp(str, "variable3"))      return BMS_TYPE_VARIABLE3;
        if(!stricmp(str, "variable4"))      return BMS_TYPE_VARIABLE4;
        if(!stricmp(str, "variable5"))      return BMS_TYPE_VARIABLE5;
        if(!stricmp(str, "unreal"))         return BMS_TYPE_VARIABLE2;
        if(!stricmp(str, "variant"))        return BMS_TYPE_VARIANT;
        if(!stricmp(str, "date"))           return BMS_TYPE_TIME;
        if(!stricmp(str, "time"))           return BMS_TYPE_TIME;
        if(!stricmp(str, "time_t"))         return BMS_TYPE_TIME;
        if(!stricmp(str, "time32"))         return BMS_TYPE_TIME;
        if(!stricmp(str, "timestamp"))      return BMS_TYPE_TIME;
        if(!stricmp(str, "date64"))         return BMS_TYPE_TIME64;
        if(!stricmp(str, "time64"))         return BMS_TYPE_TIME64;
        if(!stricmp(str, "timestamp64"))    return BMS_TYPE_TIME;
        if(!stricmp(str, "FILETIME"))       return BMS_TYPE_TIME64;
        if(!stricmp(str, "clsid"))          return BMS_TYPE_CLSID;
        if(!stricmp(str, "classid"))        return BMS_TYPE_CLSID;
        if(!stricmp(str, "uuid"))           return BMS_TYPE_CLSID;
        if(!stricmp(str, "ip"))             return BMS_TYPE_IPV4;
        if(!stricmp(str, "ipv4"))           return BMS_TYPE_IPV4;
        if(!stricmp(str, "inet4"))          return BMS_TYPE_IPV4;
        if(!stricmp(str, "ipv6"))           return BMS_TYPE_IPV6;
        if(!stricmp(str, "inet6"))          return BMS_TYPE_IPV6;
        if(!stricmp(str, "asm"))            return BMS_TYPE_ASM;
        if(!stricmp(str, "assembly"))       return BMS_TYPE_ASM;
        if(!stricmp(str, "assembler"))      return BMS_TYPE_ASM;
        if(!stricmp(str, "x86"))            return BMS_TYPE_ASM;
        if(!stricmp(str, "fullbasename"))   return BMS_TYPE_FULLBASENAME;
        if(!stricmp(str, "none"))           return BMS_TYPE_NONE;
        if(!stricmp(str, "null"))           return BMS_TYPE_NONE;
        if(!stricmp(str, "TCC"))            return BMS_TYPE_TCC;

        // ever at the end!
        if(!stricmp(str, "unknown") || !stricmp(str, "?"))  return BMS_TYPE_UNKNOWN;
        //if(!stricmp(str, "8"))              return BMS_TYPE_LONGLONG;
        if(!stricmp(str, "4"))              return BMS_TYPE_LONG;
        if(!stricmp(str, "3"))              return BMS_TYPE_THREEBYTE;
        if(!stricmp(str, "2"))              return BMS_TYPE_SHORT;
        if(!stricmp(str, "1"))              return BMS_TYPE_BYTE;

        if(strstr(str,   "64"))             return BMS_TYPE_LONGLONG;
        if(strstr(str,   "32"))             return BMS_TYPE_LONG;
        if(strstr(str,   "24"))             return BMS_TYPE_THREEBYTE;
        if(strstr(str,   "16"))             return BMS_TYPE_SHORT;
        if(strstr(str,   "8"))              return BMS_TYPE_BYTE;
        // nothing must be added here
    }
    fprintf(stderr, "\nError: invalid datatype %s at line %d\n", str, (i32)g_bms_line_number);
    myexit(QUICKBMS_ERROR_BMS);
    return -1;
}



int get_var_from_name(u8 *name, int namelen) {  // a memory_file IS NOT a variable!
    int     i;

    if(!name) return -1;
    if(namelen < 0) namelen = strlen(name);
    for(i = 0; g_variable[i].name; i++) {
        check_variable_errors(i, NULL);

        if(strlen(g_variable[i].name) != namelen) continue;

        // the following check is necessary because name may be longer than namelen
        if(!strnicmp(g_variable[i].name, name, namelen) && !g_variable[i].name[namelen]) return i;
        //if(!strnicmp(g_variable[i].name, name, namelen) && (strlen(g_variable[i].name) == namelen)) return i;
    }
    return -1;
}



int getvarnum(u8 *name, int namesz) {
    int     var;

    var = get_var_from_name(name, namesz);
    if(var >= 0) {
        return get_var32(var);
    }
    return readbase(name, 10, NULL);
}



void var_check_idx(int idx) {
    if((idx < 0) || (idx >= MAX_VARS)) {
        fprintf(stderr, "\nError: the variable index is invalid (%"PRId"), there is an error in QuickBMS\n", idx);
        myexit(QUICKBMS_ERROR_BMS);
    }
    check_variable_errors(idx, NULL);
}



int check_sub_vars(int idx, int create_if_unexistent);



/*
X1  value32
X2  value
X3  name
X4  memory_file
X5  array
*/

// do NOT enable X4 and memory files here or will be visualized an error!
#define GET_VAR_COMMON(X1,X2,X3,X4,X5) \
    int     sub_idx; \
    var_check_idx(idx); \
    if(g_variable[idx].sub_var && g_variable[idx].sub_var->active) { \
        sub_idx = check_sub_vars(idx, 0); \
        if(sub_idx < 0) { \
            fprintf(stderr, "\nError: the specified coordinates of the multidimensional array don't exist\n"); \
            myexit(QUICKBMS_ERROR_BMS); \
        } \
        return(X5); \
    } \
    if(g_variable[idx].isnum) { \
        if(g_verbose > 0) printf("             <get %s (%d) 0x%"PRIx"\n", g_variable[idx].name, (i32)idx, g_variable[idx].value32); \
        /* else if(g_verbose < 0) printf("               %-10s 0x%08x\n", g_variable[idx].name, (i32)g_variable[idx].value32); */ \
        return(X1); \
    } \
    if(g_variable[idx].value) { \
        if(g_verbose > 0) printf("             <get %s (%d) \"%s\"\n", g_variable[idx].name, (i32)idx, g_variable[idx].value); \
        /* else if(g_verbose < 0) printf("               %-10s \"%s\"\n", g_variable[idx].name, g_variable[idx].value); */ \
        return(X2); \
    } \
    if(g_variable[idx].name[0] && strnicmp(g_variable[idx].name, MEMORY_FNAME, MEMORY_FNAMESZ)) { /* "" is for sequential file names */ \
        if(g_verbose > 0) printf("- variable \"%s\" seems uninitialized, I use its name\n", g_variable[idx].name); \
        /* else if(g_verbose < 0) printf("               %-10s \"%s\"\n", g_variable[idx].name, g_variable[idx].name); */ \
        /* myexit(QUICKBMS_ERROR_BMS); */ \
    } \
    if(g_verbose > 0) printf("             <get %s (%d) \"%s\"\n", g_variable[idx].name, (i32)idx, g_variable[idx].name); \
    /* else if(g_verbose < 0) printf("               %-10s \"%s\"\n", g_variable[idx].name, g_variable[idx].name); */ \
    return(X3);



u8 *get_varname(int idx) {
    if((idx < 0) || (idx >= MAX_VARS)) {
        //fprintf(stderr, "\nError: the variable index is invalid (%"PRId"), there is an error in QuickBMS\n", idx);
        //myexit(QUICKBMS_ERROR_BMS);
        return "";
    }
    check_variable_errors(idx, NULL);
    return(g_variable[idx].name);
}



int get_var32(int idx) {
    GET_VAR_COMMON(
        g_variable[idx].value32,
        myatoi(g_variable[idx].value),
        myatoi(g_variable[idx].name),
        myatoi(g_memory_file[-get_memory_file(g_variable[idx].name)].data),
        myatoi(g_variable[idx].sub_var->array[sub_idx].data)
    )
}



u8 *get_var(int idx) {
    GET_VAR_COMMON(
        myitoa(g_variable[idx].value32),
        g_variable[idx].value,
        g_variable[idx].name,
        g_memory_file[-get_memory_file(g_variable[idx].name)].data,
        g_variable[idx].sub_var->array[sub_idx].data
    )
}



int get_var_fullsz(int idx) {
    GET_VAR_COMMON(
        strlen(myitoa(g_variable[idx].value32)),
#ifdef QUICKBMS_VAR_STATIC
        g_variable[idx].real_size,
#else
        g_variable[idx].size,
#endif
        strlen(g_variable[idx].name),
        g_memory_file[-get_memory_file(g_variable[idx].name)].size,
        g_variable[idx].sub_var->array[sub_idx].size
    )
}



int var_is_a_string(int idx) {
    GET_VAR_COMMON(
        0,
        1,
        1,
        1,
        1
    )
}



int var_is_a_number(int idx) {
    GET_VAR_COMMON(
        1,
        0,
        0,
        0,
        0
    )
}



int var_is_a_memory_file(int idx) {
    GET_VAR_COMMON(
        0,
        0,
        1,  // uhmmm correct?
        1,
        0
    )
}



int var_is_a_constant(int idx) {
    var_check_idx(idx);
    if(g_variable[idx].constant) return 1;
    return 0;
}



int var_is_a_constant_string(int idx) {
    var_check_idx(idx);
    if(!g_variable[idx].isnum) {
        if(g_variable[idx].constant) return 1;
    }
    return 0;
}



int check_sub_vars(int idx, int create_if_unexistent) {
    static int  tmp32sz = 0;
    static int  *tmp32  = NULL;
    int     i,
            sz,
            sub_idx;

    var_check_idx(idx);
    if(!g_variable[idx].sub_var) return -1;
    if(!g_variable[idx].sub_var->vars) return -1;
    sz = g_variable[idx].sub_var->vars * sizeof(int);
    if(sz > tmp32sz) {
        tmp32 = realloc(tmp32, sz);
        if(!tmp32) STD_ERR(QUICKBMS_ERROR_MEMORY);
        tmp32sz = sz;
    }
    for(i = 0; i < g_variable[idx].sub_var->vars; i++) {
        sub_idx = get_var32(g_variable[idx].sub_var->var[i]);
        if(sub_idx < 0) {
            fprintf(stderr, "\nError: the sub_variable index for the array is invalid (%"PRId"->%"PRId")\n", i, sub_idx);
            myexit(QUICKBMS_ERROR_BMS);
        }
        tmp32[i] = sub_idx;
    }
    for(i = 0; i < g_variable[idx].sub_var->arrays; i++) {
        if(!memcmp(tmp32, g_variable[idx].sub_var->array[i].info, sz)) break;
    }
    if(i >= g_variable[idx].sub_var->arrays) {
        if(!create_if_unexistent) return -1;
        if(g_variable[idx].sub_var->arrays == (u_int)-1LL) ALLOC_ERR;
        g_variable[idx].sub_var->array = realloc(g_variable[idx].sub_var->array, (g_variable[idx].sub_var->arrays + 1) * sizeof(data_t));
        if(!g_variable[idx].sub_var->array) STD_ERR(QUICKBMS_ERROR_MEMORY);
        i = g_variable[idx].sub_var->arrays;
        g_variable[idx].sub_var->arrays++;
        memset(&g_variable[idx].sub_var->array[i], 0, sizeof(data_t));
        g_variable[idx].sub_var->array[i].info = malloc_copy(NULL, tmp32, sz);
    }
    return i;
}



// I have chosen -2 because it's negative and is different than -1, a fast solution
int add_varval(int idx, /*u8 *name,*/ u8 *val, int val32, int valsz) {
    static int  force_constants_reusage = 0;
    int     sub_idx;

    if(valsz != -2) {
        if(g_variable[idx].constant) {
            //return -1; //goto quit_error;
            if(!force_constants_reusage) {
                fprintf(stderr, "\n"
                    "- Variable %d (\"%s\") at line %d is constant but the script tries to edit it.\n"
                    "  Do you want to continue anyway (y/N)?\n"
                    "  ",
                    (i32)idx, g_variable[idx].name, (i32)g_bms_line_number);
                if(get_yesno(NULL) != 'y') return -1;
                force_constants_reusage = 1;
            }
        }

        // experimental multi-dimensional arrays
        if(g_variable[idx].sub_var && g_variable[idx].sub_var->vars) {
            sub_idx = check_sub_vars(idx, 1);
            if(sub_idx < 0) {
                fprintf(stderr, "\nError: multi dimensional add_varval error\n");
                myexit(QUICKBMS_ERROR_BMS);
            }
            // do NOT use strdup_replace!
            if(!val) {
                val = myitoa(val32);
                valsz = strlen(val);
            }
            if(valsz < 0) {
                valsz = strlen(val);
                if(valsz < 0) ALLOC_ERR;
            }
            if(g_variable[idx].sub_var->array[sub_idx].size < valsz) {
                g_variable[idx].sub_var->array[sub_idx].data = realloc(g_variable[idx].sub_var->array[sub_idx].data, valsz + 2);
            }
            g_variable[idx].sub_var->array[sub_idx].size = valsz;
            memcpy(g_variable[idx].sub_var->array[sub_idx].data, val, valsz);
            g_variable[idx].sub_var->array[sub_idx].data[valsz] = 0;
            g_variable[idx].sub_var->array[sub_idx].data[valsz + 1] = 0;
            /* old version
            if(val) {
                strdup_replace(&g_variable[idx].sub_var->array[sub_idx].data, val, valsz, &g_variable[idx].sub_var->array[sub_idx].size);
                //g_variable[idx].sub_var->array[sub_idx].isnum = 0;
            } else {
                strdup_replace(&g_variable[idx].sub_var->array[sub_idx].data, myitoa(val32), -1, &g_variable[idx].sub_var->array[sub_idx].size);
                //g_variable[idx].sub_var->array[sub_idx].isnum = 1;
            }
            */
            if(!g_variable[idx].sub_var->active) g_variable[idx].sub_var->active = 1;
            return 0;
        }

        if(!val) {
            g_variable[idx].value32 = val32;
            g_variable[idx].isnum   = 1;
#ifdef QUICKBMS_VAR_STATIC
            g_variable[idx].real_size = 0;
#endif
            //val = myitoa(val32);  // commented out to improve the performances, better to never enable!
        } else {
            g_variable[idx].isnum   = 0;
        }
        if(val) {
            if(valsz < 0) {
                valsz = strlen(val);
                if(valsz < 0) ALLOC_ERR;
                g_variable[idx].binary = 0;
            } else {
                g_variable[idx].binary = 1;
            }
            /*
            if(valsz < strlen(val)) {
                fprintf(stderr, "\nError: there is an error in QuickBMS: valsz < strlen(val). Contact me!\n");
                myexit(QUICKBMS_ERROR_BMS);
            }
            */
#ifdef QUICKBMS_VAR_STATIC
            if(valsz <= VAR_VALUESZ) {
                memcpy(g_variable[idx].value_static, val, valsz);
                g_variable[idx].size = VAR_VALUESZ;   // valsz
                //g_variable[idx].value_static[valsz] = 0;
                memset(g_variable[idx].value_static + valsz, 0, (g_variable[idx].size + 1) - valsz);    // good for undelimited utf16 unicodes
                g_variable[idx].value = g_variable[idx].value_static;
            } else
#endif
            {
                strdup_replace(&g_variable[idx].value_alloc, val, valsz, &g_variable[idx].size);
                g_variable[idx].value = g_variable[idx].value_alloc;
            }
#ifdef QUICKBMS_VAR_STATIC
            g_variable[idx].real_size = valsz;
#endif
        }
    //} else {
        // avoids problems with commands like putvarchr
        // in short if the variable has no value (uninitialized) then it uses the
        // name but if this value gets reallocated then the name will continue
        // to point to the old value causing tons of problems

        // do not enable the following so the user can notice his errors,
        // for example a full script containing only:
        // putvarchr MYVAR 0x1000000 0
        //strdup_replace(&g_variable[idx].value, name, -1, &g_variable[idx].size);
    }
    return 0;
}



int *add_multi_dimensional(u8 *name, int *sub_vars);



int add_var(int idx, u8 *name, u8 *val, int val32, int valsz) {
    int     sub_vars    = 0,
            *sub_var    = NULL,
            t;

    int     is_const    = g_lame_add_var_const_workaround;
    g_lame_add_var_const_workaround = 0;


    // do NOT touch valsz, it's a job of strdup_replace
    var_check_idx(idx);
    //if((valsz == -2) && !name) name = ""; // specific for the ARGs, only in case of errors in my programming
    // if(valsz < 0) valsz = STRINGSZ;  do NOT do this, valsz is calculated on the length of val
    if(!name) {  // && (idx >= 0)) {
        //name = g_variable[idx].name; // unused
        if(add_varval(idx, val, val32, valsz) < 0) goto quit_error;
        //goto quit;
    } else {    // used only when the bms file is parsed at the beginning

        sub_var = add_multi_dimensional(name, &sub_vars);

        if(!stricmp(name, "EXTRCNT") || !stricmp(name, "BytesRead") || !stricmp(name, "NotEOF") || !stricmp(name, "SOF") || !stricmp(name, "EOF")) {
            if(!g_mex_default) {
                g_mex_default = 1;    // this avoids to waste cpu for these boring and useless variables
                g_mex_default_init(0);
            }
        }
        for(idx = 0; g_variable[idx].name; idx++) {
            // stricmp = case INSENSITIVE
            // strcmp  = case SENSITIVE
            if(g_insensitive) t = stricmp(g_variable[idx].name, name);
            else              t = strcmp(g_variable[idx].name, name);
            if(!t) {
                if(add_varval(idx, val, val32, valsz) < 0) goto quit_error;
                goto quit;
            }
        }
        if(idx >= MAX_VARS) {
            fprintf(stderr, "\nError: the script uses more variables (%"PRId") than supported\n", idx);
            myexit(QUICKBMS_ERROR_BMS);
        }


        t = strlen(name);
        if(t < 0) ALLOC_ERR;
#ifdef QUICKBMS_VAR_STATIC
        if(t <= VAR_NAMESZ) {
            memcpy(g_variable[idx].name_static, name, t + 1);
            g_variable[idx].name = g_variable[idx].name_static;
            g_variable[idx].size = VAR_NAMESZ;    // t
        } else
#endif
        {
            strdup_replace(&g_variable[idx].name_alloc, name, t, &g_variable[idx].size);
            g_variable[idx].name = g_variable[idx].name_alloc;
        }
#ifdef QUICKBMS_VAR_STATIC
        g_variable[idx].real_size = t;
#endif


        if(add_varval(idx, val, val32, valsz) < 0) goto quit_error;

        if(!g_variable[idx].name[0]) {        // ""
            g_variable[idx].constant = 1;     // it's like read-only
        }

        if(is_const) {
            g_variable[idx].constant = 1;
        } else {
            // if this "if" is removed the tool will be a bit slower but will be able to handle completely the script in the example below
            if(myisdigitstr(g_variable[idx].name)) {  // removes the problem of Log "123.txt" 0 0
            //if(myisdigit(g_variable[idx].name[0])) {  // number: why only the first byte? because decimal and hex (0x) start all with a decimal number or a '-'
                //strdup_replace(&g_variable[idx].value, g_variable[idx].name, -1, &g_variable[idx].size);
                g_variable[idx].value32  = myatoi(g_variable[idx].name);
                g_variable[idx].isnum    = 1;
                g_variable[idx].constant = 1;     // it's like read-only

                // there is only one incompatibility with the string-only variables, but it's acceptable for the moment:
                //   set NAME string "mytest"
                //   set NUM long 0x1234
                //   string NAME += NUM
                //   print "%NAME%"
                //   set NUM string "0x12349999999999"
                //   string NAME += NUM
                //   print "%NAME%"
            }
        }

        if(sub_var) {
            g_variable[idx].sub_var = calloc(sizeof(sub_variable_t), 1);
            if(!g_variable[idx].sub_var) STD_ERR(QUICKBMS_ERROR_MEMORY);
            g_variable[idx].sub_var->var  = sub_var;
            g_variable[idx].sub_var->vars = sub_vars;
        }
    }
quit:
    if(g_verbose > 0) {
        if(g_variable[idx].isnum) {
            printf("             >set %s (%"PRId") to 0x%"PRIx"\n", g_variable[idx].name, idx, g_variable[idx].value32);
        } else if(g_variable[idx].value) {
            printf("             >set %s (%"PRId") to \"%s\"\n", g_variable[idx].name, idx, g_variable[idx].value);
        } else {
            printf("             >set %s (%"PRId") to \"%s\"\n", g_variable[idx].name, idx, g_variable[idx].name);
        }
    /*} else if(g_verbose < 0) {
        if(g_variable[idx].isnum) {
            printf("             >%-10s 0x%"PRIx"\n", g_variable[idx].name, g_variable[idx].value32);
        } else if(g_variable[idx].value) {
            printf("             >%-10s \"%s\"\n", g_variable[idx].name, g_variable[idx].value);
        } else {
            printf("             >%-10s \"%s\"\n", g_variable[idx].name, g_variable[idx].name);
        } */
    }
    return(idx);
quit_error:
    fprintf(stderr, "\nError: there is something wrong in the BMS script, please check it\n");
    myexit(QUICKBMS_ERROR_BMS);
    return -1;
}



#define add_var_const(A, B, C, D, E) \
    add_var( \
        ((g_lame_add_var_const_workaround = 1) & 0) + A, \
        B, C, D, E)



int *add_multi_dimensional(u8 *name, int *sub_vars) {
    int     ret = 0,
            op  = 0,
            cl  = 0,
            *sub_var    = NULL;
    u8      *s,
            *p,
            *l;

    if(sub_vars) *sub_vars = 0;
    if(!name) return NULL;

    for(s = name; *s; s++) {
        if(*s == '[') op++;
        if(*s == ']') {
            cl++;
            if(op != cl) return NULL;
        }
    }
    if(op != cl) {                      // [[asdf]
        //fprintf(stderr, "\nError: add_multi_dimensional with different number of [ and ]\n");
        //myexit(QUICKBMS_ERROR_BMS);
        return NULL;
    }
    if(!op) return NULL;               // ]
    if(!cl) return NULL;               // [

    sub_var = calloc(op, sizeof(int));
    if(!sub_var) STD_ERR(QUICKBMS_ERROR_MEMORY);

    p = NULL;
    l = NULL;
    for(s = name; *s; s++) {
        if(*s == '[') {
            p = s;
            l = NULL;
            continue;
        } else if(*s == ']') {
            l = s;
        } else {
            continue;
        }
        if(!p || (l < p)) {
            fprintf(stderr, "\nError: add_multi_dimensional error\n");
            myexit(QUICKBMS_ERROR_BMS);
        }
        *p = 0;
        *l = 0;
        sub_var[ret] = add_var(0, p + 1, NULL, 0, -2);
        *p = '[';
        *l = ']';
        p = NULL;
        l = NULL;
        ret++;
    }
    *sub_vars = ret;
    return(sub_var);
}



// this function is a partial work-around
int quick_var_from_name_check(u8 **ret_key, int *ret_keysz) {
    int     keysz   = -1,
            idx     = -1;
    u8      *key,
            *p;

    if(!ret_key || !*ret_key) return -1;
    if(ret_keysz) keysz = *ret_keysz;
    if(keysz >= (NUMBERSZ + 1)) return -1;  // it's useless to make the check for keys over this size
    key = *ret_key;

    // it's necessary to check the memory_file before the variable or it will not work
    if(!strnicmp(key, MEMORY_FNAME, MEMORY_FNAMESZ)) {   // memory_file
        idx   = -get_memory_file(key);
        keysz = g_memory_file[idx].size;
        key   = g_memory_file[idx].data;
    } else {
        idx = get_var_from_name(key, keysz);
        if(idx >= 0) {  // variable
            p = get_var(idx);
            if(p) {
                keysz = get_var_fullsz(idx);
                key   = p;
            }
        }
    }

    if(!key || (keysz < 0)) return -1; // something was wrong so avoid it

    if(ret_keysz) *ret_keysz = keysz;
    *ret_key = key;
    return idx;
}



u8 *bad_chars_filter(u8 *s, int len) {
    int     i;

    for(i = 0; i < len; i++) {
        if(!s[i]) break;
        //if(!isprint(s[i])) return "";    // doesn't work on linux
        //if(s[i] == '\r') continue;    // one line only
        //if(s[i] == '\n') continue;    // one line only
        if((s[i] >= ' ') && (s[i] < 0x7f)) continue;
        return "";
    }
    if(s[i]) return "";
    return s;
}



int verbose_print(int offset, u8 *cmd, int idx, u8 *str, i32 strsz, int num, i32 more) {
    i32     len;
    u8      *name;

    name = get_varname(idx);
    if(!strcmp(name, QUICKBMS_DUMMY)) return -1;   // no need of stricmp
    if(str) {
        len = strsz;
        if(strsz < 0) len = strlen(str);
        printf(". %"PRIx" %-7s %-10s \"%.*s\" %d\n", offset, cmd, name, len, bad_chars_filter(str, len), more);
        //printf(". %"PRIx" %-7s %-10s \"%.*s\" %d (line %d)\n", offset, cmd, name, len, bad_chars_filter(str, len), more, (i32)g_bms_line_number);
        if(strsz > 0) show_dump(4, str, strsz, stdout);
    } else {
        printf(". %"PRIx" %-7s %-10s 0x%"PRIx" %d\n", offset, cmd, name, num, more);
        //printf(". %"PRIx" %-7s %-10s 0x%"PRIx" %d (line %d)\n", offset, cmd, name, num, more, (i32)g_bms_line_number);
    }
    return 0;
}



void variable_copy(variable_t *output, variable_t *input, int keep_content) {
    int     i;
    u8      *name_alloc                     = NULL,
#ifdef QUICKBMS_VAR_STATIC
            *name                           = NULL,
            name_static[VAR_NAMESZ + 1]     = "",
            *value                          = NULL,
            value_static[VAR_VALUESZ + 1]   = "",
#endif
            *value_alloc                    = NULL;

    if(!output || !input) return;

#ifdef QUICKBMS_VAR_STATIC
    memset(value_static, 0, sizeof(value_static));  // useful
#endif
    
    if(keep_content) {
        name_alloc = output->name_alloc;
#ifdef QUICKBMS_VAR_STATIC
        if(output->name == output->name_static) {
            strncpy(name_static, output->name, VAR_NAMESZ + 1);
            name = name_static;
        } else {
            name = name_alloc;
        }
#endif

        value_alloc = output->value_alloc;
#ifdef QUICKBMS_VAR_STATIC
        if(output->value == output->value_static) {
            if(output->size > VAR_VALUESZ) STD_ERR(QUICKBMS_ERROR_BMS);
            memcpy(value_static, output->value_static, output->size + 1); //VAR_VALUESZ + 1);
            value = value_static;
        } else {
            value = value_alloc;
        }
#endif
    }

    memcpy(output, input, sizeof(variable_t));

    if(keep_content) {
        output->name_alloc = name_alloc;
#ifdef QUICKBMS_VAR_STATIC
        if(name == name_static) {
            strncpy(output->name_static, name_static, VAR_NAMESZ + 1);
            output->name = output->name_static;
        } else
#endif
        {
            output->name = output->name_alloc;
        }

        output->value_alloc = value_alloc;
#ifdef QUICKBMS_VAR_STATIC
        if(value == value_static) {
            if(output->size > VAR_VALUESZ) value = value_alloc; // ???
        }
        if(value == value_static) {
            if(output->size > VAR_VALUESZ) STD_ERR(QUICKBMS_ERROR_BMS);
            memcpy(output->value_static, value_static, output->size + 1); //VAR_VALUESZ + 1);
            output->value = output->value_static;
        } else
#endif
        {
            output->value = output->value_alloc;
        }

    } else {
        output->name = NULL;
        output->name_alloc = NULL;
#ifdef QUICKBMS_VAR_STATIC
        output->name_static[0] = 0;     //memset(output->name_static, 0, VAR_NAMESZ + 1);
#endif

        if(!input->name) {
#ifdef QUICKBMS_VAR_STATIC
        } else if(input->name == input->name_static) {  // don't use strlen, consider possible binary names
            strncpy(output->name_static, input->name, VAR_NAMESZ + 1);
            output->name = output->name_static;
#endif
        } else {
            re_strdup(&output->name_alloc, input->name, NULL); // not needed
            output->name = output->name_alloc;
        }

        output->value = NULL;
        output->value_alloc = NULL;
#ifdef QUICKBMS_VAR_STATIC
        output->value_static[0] = 0;    //memset(output->value_static, 0, VAR_VALUESZ + 1);
#endif
    }

    if(input->value) {
        if(output->size == (u_int)-1LL) ALLOC_ERR;
#ifdef QUICKBMS_VAR_STATIC
        if(output->size <= VAR_VALUESZ) {
            output->value = output->value_static;
        } else
#endif
        {
            myalloc(&output->value_alloc, output->size + 1, NULL); /* lame, there is a heap corruption mah... */
            output->value = output->value_alloc;
        }
        memcpy(output->value, input->value, output->size);
        output->value[output->size] = 0; /* final NULL byte or just memcpy output->size + 1 */
#ifdef QUICKBMS_VAR_STATIC
        if(output->size <= VAR_VALUESZ) output->size = VAR_VALUESZ;
#endif
    } else {
        // output->value = input->name

        if(keep_content) {
            if(!input->name) {
                output->value = NULL;
                output->size = 0;
#ifdef QUICKBMS_VAR_STATIC
            } else if(input->name == input->name_static) {  // consider names with binary data so avoid strlen
                strncpy(output->value_static, input->name, VAR_VALUESZ + 1);    // never use memcpy
                output->value = output->value_static;
                output->size = VAR_NAMESZ; //strlen(output->value);   // output->size = input->size ???
#endif
            } else {
                strdup_replace(&output->value_alloc, input->name, -1, &output->size);   // old method
                output->value = output->value_alloc;
            }
        }
    }

    if(input->sub_var) {
        output->sub_var        = malloc_copy(keep_content ? output->sub_var        : NULL, input->sub_var,        sizeof(sub_variable_t));
        output->sub_var->var   = malloc_copy(keep_content ? output->sub_var->var   : NULL, input->sub_var->var,   input->sub_var->vars * sizeof(int));
        output->sub_var->array = malloc_copy(keep_content ? output->sub_var->array : NULL, input->sub_var->array, input->sub_var->arrays * sizeof(data_t));
        for(i = 0; i < input->sub_var->arrays; i++) {
            output->sub_var->array[i].info = malloc_copy(keep_content ? output->sub_var->array[i].info : NULL, input->sub_var->array[i].info, input->sub_var->vars * sizeof(int));
            output->sub_var->array[i].data = malloc_copy(keep_content ? output->sub_var->array[i].data : NULL, input->sub_var->array[i].data, input->sub_var->array[i].size);
        }
    }

    output->constant = 0;
}



void FREE_VAR(variable_t *X) {
    int     i;

    if(!X) return;
    X->name  = NULL;
    X->value = NULL;
    FREE(X->name_alloc)
    FREE(X->value_alloc)
    if(X->sub_var) {
        FREE(X->sub_var->var)
        for(i = 0; i < X->sub_var->arrays; i++) {
            FREE(X->sub_var->array[i].info)
            FREE(X->sub_var->array[i].data)
        }
        FREE(X->sub_var->array)
        FREE(X->sub_var)
    }
    //memset(X, 0, sizeof(variable_t)); // not needed
}

