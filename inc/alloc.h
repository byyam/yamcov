/****************************************************
 *
 * This is a tool help to research gcda/gcno in gcc.
 * Author:YamCheung
 * email:yanzhang.scut@gmail.com
 *
 * **************************************************
 * */
#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>
#include <string.h>



char *xstr(int len, gcov_unsigned_t *ptr) {
    char *str = NULL;
    str = (char *)malloc(len + 1);
    memcpy(str, ptr, len);
    str[len] = '\0';
    return str;
}


#define PTR void *


PTR bcalloc(size_t nelem, size_t elsize) {
    register PTR ptr;

    if (nelem == 0 || elsize == 0)
        nelem = elsize = 1;

    ptr = malloc(nelem*elsize);

    if(ptr)
        bzero(ptr, nelem*elsize);

    return ptr;
}

PTR xcalloc(size_t nelem, size_t elsize) {
    PTR newmem;

    if (nelem == 0 || elsize == 0)
        nelem = elsize = 1;
    newmem = bcalloc(nelem, elsize);

    return (newmem);
}


#define XCNEW(T)            ((T *)xcalloc(1, sizeof(T)))
#define XCNEWVEC(T, N)      ((T *)xcalloc((N), sizeof(T)))




#endif
