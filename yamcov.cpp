/****************************************************
 *
 * This is a tool help to research gcda/gcno in gcc.
 * Author:YamCheung
 * email:yanzhang.scut@gmail.com
 *
 * **************************************************
 * */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>


#include <iostream>
#include <vector>

using namespace std;

#include "yamcov_io.h"
#include "yamcov.h"
#include "alloc.h"

static function_t *functions;
static source_t *sources;
static unsigned source_index;


global_t global_summary;

int ret_code;




/***************************DEBUG***********************************/


void print_binary(char *sz, long size) {
    gcov_unsigned_t *ptr = (gcov_unsigned_t *)sz;
    int each_line = 4;
    int i;
    printf("file size:   %4lu bytes\n", size);
    printf("each line:   %4d bytes\n", each_line*sizeof(gcov_unsigned_t));
    printf("word length: %4d bytes\n", sizeof(gcov_unsigned_t));
    printf("file block:  %4d (each line has %d blocks)\n", size/sizeof(gcov_unsigned_t), each_line);
    for (i = 0; i < (size/sizeof(gcov_unsigned_t)); i++) {
        if (i % each_line == 0 ) {
            printf("\n");
            printf("[%04d]%08d: ", i, i*(sizeof(gcov_unsigned_t)));
        }
        printf("%08x ", *(ptr+i));
    }
    printf("\n");
}

void __print_info(gcov_info *gcda_obj) {
    printf("file size: %ld, record number: %ld\n", gcda_obj->file_size, gcda_obj->data_num);
    printf("\nprint the gcda header info: |magic|version|stamp|\n");
    gcov_unsigned_t *header = gcda_obj->header_buf;
    int i;
    for (i = 0; i < GCDA_HEADER_LENGTH; i++) {
        printf("%08x\n", *(header + i));
    }
    record_info *record_header = gcda_obj->data;
    record_info *p_cur;
    gcov_unsigned_t *ptr;
    printf("\nprint the gcda record info: |tag|length|record|\n");
    for (p_cur = record_header; p_cur != NULL; p_cur = p_cur->next) {
        ptr = p_cur->tag;
        for (i = 0; i < GCDA_RECORD_TAG_LENGTH; i++) {
            printf("%08x\n", *(ptr+i));
        }
        ptr = p_cur->length;
        for (i = 0; i < GCDA_RECORD_LENGTH_LENGTH; i++) {
            printf("%08x\n", *(ptr+i));
        }
        ptr = p_cur->record;
        for (i = 0; i < *p_cur->length; i++) {
            if (i%4 == 0 && i != 0) {
                printf("\n");
            }
            printf("%08x ", *(ptr+i));
        }
        printf("\n===================================\n");
    }
}


void print_info(gcov_info *gcda_list) {
    gcov_info *gcda_node;
    for (gcda_node = gcda_list; gcda_node != NULL; gcda_node = gcda_node->next) {
        __print_info(gcda_node);
    }
}


static void print_program(program_summary pro) {
    printf("num     :    %ld\n", pro.num);
    printf("runs    :    %ld\n", pro.runs);
    printf("sum_all :    %08x %08x\n", (gcov_unsigned_t)pro.sum_all, (gcov_unsigned_t)(pro.sum_all >> 32));
    printf("run_max :    %08x %08x\n", (gcov_unsigned_t)pro.run_max, (gcov_unsigned_t)(pro.run_max >> 32));
    printf("sum_max :    %08x %08x\n", (gcov_unsigned_t)pro.sum_max, (gcov_unsigned_t)(pro.sum_max >> 32));
}




/***************************GCOV IO***********************************/



static int __clean_gcov(gcov_info **obj) {
    record_info *p_cur, *p_node;
    gcov_info *gcov_obj = *obj;

    for (p_cur = gcov_obj->data; p_cur != NULL; p_cur = p_node) {
        p_node = p_cur->next;
        free(p_cur);
    }
    free(p_cur);

    char *buf;
    buf = gcov_obj->buf;
    free(buf);
    return 0;
}

static int clean_gcov(gcov_info **gcov_list) {
    gcov_info *p_cur, *p_node;
    for (p_cur = *gcov_list; p_cur != NULL; p_cur = p_node) {
        __clean_gcov(&p_cur);

        p_node = p_cur->next;
        free(p_cur);
    }
    free(p_cur);
    return 0;
}

static int read_buf(char *file, long *file_size, char **file_buf) {
    print_debug(DEBUG, "reading file: %s\n", file);

    FILE *fd;
    size_t result;

    fd = fopen(file, "rb");
    if (fd == NULL) {
        print_debug(CRITICAL, "read_buf::fopen open %s error\n", file);
        return ERROR_OPEN_FILE;
    }

    fseek(fd, 0, SEEK_END);
    *file_size = ftell(fd);
    rewind(fd);

    *file_buf = (char *)malloc(sizeof(char)*(*file_size));
    char *buf = *file_buf;
    if (buf == NULL) {
        print_debug(CRITICAL, "read_buf::malloc memory allocate error\n");
        fclose(fd);
        return ERROR_MEMORY_ALLOCATE;
    }

    result = fread(buf, sizeof(char), *file_size, fd);
    if (result != *file_size) {
        print_debug(CRITICAL, "read_buf::fread reading %s error\n", file);
        fclose(fd);
        return ERROR_READ_FILE;
    }

    if (fclose(fd) != 0) {
        print_debug(ERROR, "read_buf::fclose close %s error\n", file);
        return ERROR_CLOSE_FILE;
    }

    print_debug(DEBUG, "read_buf::file_name: %s, file_size: %d\n", file, *file_size);
    return 0;
}


static int get_gcov_info(char *sz, long size, gcov_info **gcda_obj) {
    int i;
    gcov_unsigned_t *pf = (gcov_unsigned_t *)sz;
    gcov_unsigned_t *postion;
    record_info *record_header, *p_cur;
    record_header = NULL;

    *gcda_obj = (gcov_info *)malloc(sizeof(gcov_info));
    gcov_info *node = *gcda_obj;
    if (node == NULL) {
        print_debug(CRITICAL, "get_gcov_info::malloc gcov_info memory allocate error\n");
        return(ERROR_MEMORY_ALLOCATE);
    }
    node->buf = sz;
    node->file_size = size;
    node->header_buf = pf;

    node->data_num = 0;

    for (i = GCDA_HEADER_LENGTH; i < (size/sizeof(gcov_unsigned_t) - 1); node->data_num++) {
        postion = pf + i;
        record_info *precord = NULL;
        precord = (record_info *)malloc(sizeof(record_info));
        if (precord == NULL) {
            print_debug(CRITICAL, "get_gcov_info::malloc record_info memory allocate error\n");
            return(ERROR_MEMORY_ALLOCATE);
        }
        precord->tag = postion;
        precord->length = postion + GCDA_RECORD_TAG_LENGTH;
        precord->record = postion + GCDA_RECORD_TAG_LENGTH + GCDA_RECORD_LENGTH_LENGTH;
        precord->next = NULL;
        if (record_header == NULL) {
            record_header = precord;
            p_cur = record_header;
        } else {
            p_cur->next = precord;
            p_cur = p_cur->next;
        }
        i = i + GCDA_RECORD_TAG_LENGTH + GCDA_RECORD_LENGTH_LENGTH + *precord->length;
    }
    p_cur->next = NULL;

    node->data = record_header;
    node->next = NULL;

    return 0;
}



/***************************MERGE GCDA***********************************/

static int read_gcda(char *file, gcov_info **obj) {
    char *buf = NULL;
    long file_size = 0;

    if ((ret_code = read_buf(file, &file_size, &buf)) != 0) {
        print_debug(ERROR, "read_gcda::read_buf failed.[%d]\n", ret_code);
        return ret_code;
    }

    if (buf == NULL) {
        print_debug(ERROR, "read_gcda::read_buf buf is NULL.\n");
        return ERROR_READ_FILE;
    }

    if (file_size == 0) {
        print_debug(DEBUG, "read_gcda::file name: %s is empty, will not handle.\n", file);
        return ERROR_EMPTY_FILE;
    }

    #ifdef DEBUG_READ_FILE
        print_binary(buf, file_size);
    #endif

    print_debug(DEBUG, "read_gcda::get_info file: %s\n", file);
    if ((ret_code = get_gcov_info(buf, file_size, obj)) != 0) {
        print_debug(ERROR, "read_gcda::get_gcov_info failed[%d]\n", ret_code);
        return ret_code;
    }
    return 0;
}

static int read_gcda_list(int file_count, char** file_name_list, gcov_info **gcda_list) {
    gcov_info *ptr, *node;
    ptr = NULL;

    int ix;
    for (ix = optind + 1; ix < file_count; ix++) {
        node = NULL;
        ret_code = read_gcda(file_name_list[ix], &node);
        if (ret_code == ERROR_EMPTY_FILE) {
            continue;
        } else if (ret_code != 0) {
            print_debug(ERROR, "read_gcda_list::read_gcda failed[%d]\n", ret_code);
            return ERROR_OPEN_FILE;
        }

        if (node == NULL) {
            print_debug(ERROR, "read_gcda_list::read_gcda node is null.\n");
            return ERROR_READ_FILE;
        }

        print_debug(DEBUG, "read_gcda_list::read_gcda finish. %s\n", file_name_list[ix]);

        if (*gcda_list == NULL) {
            *gcda_list = node;
            ptr = *gcda_list;
        } else {
            ptr->next = node;
            ptr = ptr->next;
        }
    }
    if (ptr) {
        ptr->next = NULL;
    }
    return 0;
}


static int write_gcda(gcov_info *gcda_obj) {
    FILE *fd;
    size_t result;

    fd = fopen(global_summary.out_file, "wb");
    if (fd == NULL) {
        print_debug(ERROR, "write_gcda::fopen open %s error\n", global_summary.out_file);
        return ERROR_OPEN_FILE;
    }

    print_debug(DEBUG, "write merge gcda to file: %s\n", global_summary.out_file);
    result = fwrite(gcda_obj->buf, sizeof(char), gcda_obj->file_size, fd);
    if (result != gcda_obj->file_size) {
        print_debug(ERROR, "write_gcda::fwrite writing %s error\n", global_summary.out_file);
        return ERROR_WRITE_FILE;
    }

    if (fclose(fd) != 0) {
        print_debug(ERROR, "write_gcda::fclose close %s error\n", global_summary.out_file);
        return ERROR_CLOSE_FILE;
    }
    return 0;
}

static void gcov_read_ctr(gcov_type *ctr, gcov_unsigned_t *ptr) {
    gcov_unsigned_t *t = (gcov_unsigned_t *)ctr;
    *t = *ptr;
    *(t + 1) = *(ptr + 1);
}

static void gcov_add_ctr(gcov_type *t_ctr, gcov_type *n_ctr) {
    gcov_type value;
    gcov_unsigned_t *t = (gcov_unsigned_t *)t_ctr;
    gcov_unsigned_t *n = (gcov_unsigned_t *)n_ctr;
    if (sizeof(gcov_type) > sizeof(gcov_unsigned_t)) {
        value = *(t + 1) + *(n + 1);
    } else {
        value = 0;
    }
    value += *t + *n;
    print_debug(DEBUG, "t_ctr: %016x\n", *t_ctr);
    print_debug(DEBUG, "n_ctr: %016x\n", *n_ctr);
    print_debug(DEBUG, "value: %016x\n", value);

    *t = (gcov_unsigned_t)value;
    if (sizeof(gcov_type) > sizeof(gcov_unsigned_t)) {
        *(t + 1) = (gcov_unsigned_t)(value >> 32);
    } else {
        *(t + 1) = 0;
    }
}

static void gcov_max_ctr(gcov_type *t_ctr, gcov_type *n_ctr) {
    gcov_unsigned_t *t = (gcov_unsigned_t *)t_ctr;
    gcov_unsigned_t *n = (gcov_unsigned_t *)n_ctr;

    if (*(t + 1) < *(n + 1) || (*(t + 1) == *(n + 1) && *t < *n)) {
        *t_ctr = *n_ctr;
    }
}


static void merge_counter(record_info *target, record_info *node) {
    int i;
    gcov_unsigned_t *blk_t, *blk_n;
    blk_t = target->record;
    blk_n = node->record;
    for (i = 0; i < *target->length; i++) {
        *(blk_t + i) = *(blk_t + i) + *(blk_n + i);
    }
}


static void merge_program(record_info *target, record_info *node) {
    program_summary t_ctr, n_ctr;

    int offset = 0;
    t_ctr.num = *(target->record + (++offset));
    t_ctr.runs = *(target->record + (++offset));
    gcov_read_ctr(&t_ctr.sum_all, target->record + (++offset));
    offset += GCOV_TYPE_LEN;
    gcov_read_ctr(&t_ctr.run_max, target->record + offset);
    offset += GCOV_TYPE_LEN;
    gcov_read_ctr(&t_ctr.sum_max, target->record + offset);

    offset = 0;
    n_ctr.num = *(node->record + (++offset));
    n_ctr.runs = *(node->record + (++offset));
    gcov_read_ctr(&n_ctr.sum_all, node->record + (++offset));
    offset += GCOV_TYPE_LEN;
    gcov_read_ctr(&n_ctr.run_max, node->record + offset);
    offset += GCOV_TYPE_LEN;
    gcov_read_ctr(&n_ctr.sum_max, node->record + offset);

    #ifdef DEBUG_MERGE_GCDA
        print_program(t_ctr);
        print_program(n_ctr);
    #endif

    t_ctr.runs += n_ctr.runs;
    gcov_add_ctr(&t_ctr.sum_all, &n_ctr.sum_all);
    gcov_max_ctr(&t_ctr.run_max, &n_ctr.run_max);
    gcov_add_ctr(&t_ctr.sum_max, &n_ctr.sum_max);

    offset = 0;
    *(target->record + (++offset)) = t_ctr.num;
    *(target->record + (++offset)) = t_ctr.runs;
    *(target->record + (++offset)) = t_ctr.sum_all;
    offset += GCOV_TYPE_LEN;
    *(target->record + offset) = t_ctr.run_max;
    offset += GCOV_TYPE_LEN;
    *(target->record + offset) = t_ctr.sum_max;

    #ifdef DEBUG_MERGE_GCDA
        print_program(t_ctr);
    #endif
}


static void merge_object(record_info *target, record_info *node) {
    merge_program(target, node);
}

static int exec_merge(gcov_info *gcda_list) {
    gcov_info *merge_node, *gcda_node;
    merge_node = gcda_list;
    for (gcda_node = merge_node->next; gcda_node != NULL; gcda_node = gcda_node->next) {
        record_info *ptr, *mtr;
        long pos;
        long record_num = gcda_node->data_num;
        mtr = merge_node->data;
        ptr = gcda_node->data;
        for (pos = 0; pos < record_num; pos++) {
            print_debug(INFO, "[%ld]%08x\n", pos, *(ptr->tag));
            switch(*(ptr->tag)) {
                case GCOV_TAG_FUNCTION:
                    print_debug(INFO, "GCOV_TAG_FUNCTION: not merge\n");
                    break;
                case GCOV_TAG_COUNTER_BASE:
                    print_debug(INFO, "GCOV_TAG_COUNTER_BASE: merge\n");
                    merge_counter(mtr, ptr);
                    break;
                case GCOV_TAG_OBJECT_SUMMARY:
                    print_debug(INFO, "GCOV_TAG_OBJECT_SUMMARY: merge\n");
                    merge_object(mtr, ptr);
                    break;
                case GCOV_TAG_PROGRAM_SUMMARY:
                    print_debug(INFO, "GCOV_TAG_PROGRAM_SUMMARY: partial merge\n");
                    merge_program(mtr, ptr);
                    break;
                default:
                    print_debug(ERROR, "UNKNOWN TAG: %08x\n", *(ptr->tag));
            }
            ptr = ptr->next;
            mtr = mtr->next;
        }
    }
    if ((ret_code = write_gcda(merge_node)) != 0) {
        print_debug(ERROR, "exec_merge::write_gcda failed[%d].\n", ret_code);
        return ret_code;
    }
    return 0;
}


static int merge_gcda(int file_count, char** file_name_list) {
    gcov_info *gcda_list = NULL;
    if ((ret_code = read_gcda_list(file_count, file_name_list, &gcda_list)) != 0) {
        print_debug(CRITICAL, "merge_gcda::read_gcda_list failed[%d]\n", ret_code);
        return ret_code;
    }
    print_debug(DEBUG, "read_gcda_list finish.\n");

    #ifdef DEBUG_READ_FILE
        print_info(gcda_list);
    #endif

    if (gcda_list == NULL) {
        print_debug(ERROR, "merge_gcda::read_gcda_list gcdalist is null, read gcda file all failed(or all empty gcda).\n");
        return ERROR_READ_FILE;
    }

    if ((ret_code = exec_merge(gcda_list)) != 0) {
        print_debug(ERROR, "merge_gcda::exec_merge failed.\n");
        return ret_code;
    }
    if ((ret_code = clean_gcov(&gcda_list)) != 0) {
        print_debug(ERROR, "merge_gcda::clean_gcov failed.\n");
        return ret_code;
    }

    return 0;
}


/***************************READ COUNTER***********************************/

static void release_structures (void) {
    function_t *fn;

    while ((fn = functions)) {
        unsigned ix;
        block_t *block;

        functions = fn->next;
        for (ix = fn->num_blocks, block = fn->blocks; ix--; block++) {
            arc_t *arc, *arc_n;

            for (arc = block->succ; arc; arc = arc_n) {
                arc_n = arc->succ_next;
                free(arc);
            }
        }
        free(fn->blocks);
        free(fn->counts);
    }
}

static gcov_unsigned_t gcov_read_unsigned(gcov_unsigned_t *ptr, int *offset) {
    gcov_unsigned_t value = *(ptr + *offset);
    *offset += 1;
    return value;
}


static gcov_type gcov_get_ctr(gcov_type *ctr) {
    gcov_type value;
    gcov_unsigned_t *t = (gcov_unsigned_t *)ctr;
    if (sizeof(gcov_type) > sizeof(gcov_unsigned_t)) {
        value = *(t+1);
    } else {
        value = 0;
    }
    value += *t;
    return value;
}



static source_t *find_source (char *file_name) {
    source_t *src;

    for (src = sources; src; src = src->next)
        if (!strcmp(file_name, src->name))
            break;

    if (!src) {
        src = XCNEW(source_t);
        src->name = file_name;
        src->coverage.name = src->name;

        src->index = source_index++;

        src->next = sources;
        src->functions = NULL;
        sources = src;
    }
    return src;
}


static int read_graph_file (gcov_info *node) {
    record_info *ptr;
    long pos;
    int func_id = 0;
    long record_num = node->data_num;
    ptr = node->data;

    unsigned version;
    unsigned current_tag = 0;
    struct function_info *fn = NULL;
    function_t *old_functions_head = functions;
    source_t *src = NULL;
    unsigned ix, i;
    unsigned tag;
    unsigned length;

    for (pos = 0; pos < record_num; pos++) {
        tag = *(ptr->tag);
        length = *(ptr->length);
        print_debug(DEBUG, "[%ld]%08x\n", pos, tag);

        if (tag == GCOV_TAG_FUNCTION) {
            print_debug(INFO, "GCOV_TAG_FUNCTION:\n");

            fn = XCNEW(function_t);
            if (fn == NULL) {
                print_debug(ERROR, "read_graph_file::XCNEW fn failed.\n");
                return ERROR_MEMORY_ALLOCATE;
            }
            int len, offset = 0;
            source_t *src;
            function_t *probe, *prev;

            fn->ident = gcov_read_unsigned(ptr->record, &offset);
            fn->checksum = gcov_read_unsigned(ptr->record, &offset);

            int func_len = gcov_read_unsigned(ptr->record, &offset);
            len = func_len*(sizeof(gcov_unsigned_t)/sizeof(char));
            char *function_name = xstr(len, ptr->record + offset);
            if (function_name == NULL) {
                print_debug(ERROR, "read_graph_file::xstr function_name failed.\n");
                return ERROR_MEMORY_ALLOCATE;
            }
            fn->name = function_name;
            offset += func_len;

            int src_len = gcov_read_unsigned(ptr->record, &offset);
            len = src_len*(sizeof(gcov_unsigned_t)/sizeof(char));
            char *src_name = xstr(len, ptr->record + offset);
            if (src_name == NULL) {
                print_debug(ERROR, "read_graph_file::xstr src_name failed.\n");
                return ERROR_MEMORY_ALLOCATE;
            }
            src = find_source(src_name);
            offset += src_len;

            fn->src = src;

            int lineno = gcov_read_unsigned(ptr->record, &offset);
            fn->line = lineno;

            print_debug(DEBUG, "id: %d, name: %s, src: %s, lineno: %d\n", fn->ident, fn->name, fn->src->name, fn->line);

            fn->next = functions;
            functions = fn;
            current_tag = tag;

            if (lineno >= src->num_lines)
                src->num_lines = lineno + 1;

            for (probe = src->functions, prev = NULL;
                 probe && probe->line > lineno;
                 prev = probe, probe = probe->line_next)
                    continue;

            fn->line_next = probe;
            if (prev)
                prev->line_next = fn;
            else
                src->functions = fn;
        } else if (fn && tag == GCOV_TAG_BLOCKS) {
            print_debug(DEBUG, "GCOV_TAG_BLOCKS:\n");

            if (fn->blocks) {
                print_debug(ERROR, "already seen this blocks.\n");
                return ERROR_GCNO_FORMAT;
            }

            fn->num_blocks = *(ptr->length);
            fn->blocks = XCNEWVEC (block_t, fn->num_blocks);

            for (ix = 0; ix < fn->num_blocks; ix++) {
                fn->blocks[ix].flags = *(ptr->record + ix);
                print_debug(DEBUG, "block: %d, flag: %08x\n", ix, fn->blocks[ix].flags);
            }
        } else if (fn && tag == GCOV_TAG_ARCS) {
            print_debug(DEBUG, "GCOV_TAG_ARCS:\n");

            unsigned src = *(ptr->record);
            unsigned num_dests = (*(ptr->length) - 1)/2;

            if (src >= fn->num_blocks || fn->blocks[src].succ) {
                print_debug(ERROR, "arcs error. src: %d, blocknum: %d, succ: %s\n", src, fn->num_blocks, fn->blocks[src].succ);
                return ERROR_GCNO_FORMAT;
            }

            gcov_unsigned_t *p = ptr->record + 1;
            while (num_dests--) {
                struct arc_info *arc;
                unsigned dest = *p;
                p++;
                unsigned flags = *p;
                p++;

                if (dest >= fn->num_blocks) {
                    print_debug(ERROR, "num_blocks error.\n");
                    return ERROR_GCNO_FORMAT;
                }
                arc = XCNEW(arc_t);

                arc->dst = &fn->blocks[dest];
                arc->src = &fn->blocks[src];

                arc->count = 0;
                arc->count_valid = 0;
                arc->on_tree = !!(flags & GCOV_ARC_ON_TREE);
                arc->fake = !!(flags & GCOV_ARC_FAKE);
                arc->fall_through = !!(flags & GCOV_ARC_FALLTHROUGH);

                arc->succ_next = fn->blocks[src].succ;
                fn->blocks[src].succ = arc;
                fn->blocks[src].num_succ++;

                arc->pred_next = fn->blocks[dest].pred;
                fn->blocks[dest].pred = arc;
                fn->blocks[dest].num_pred++;

                if (arc->fake) {
                    if (src) {
                        fn->blocks[src].is_call_site = 1;
                        arc->is_call_non_return = 1;
                    } else {
                        arc->is_nonlocal_return = 1;
                        fn->blocks[dest].is_nonlocal_return = 1;
                    }
                }

                if (!arc->on_tree)
                    fn->num_counts++;

                print_debug(DEBUG, "[%d]src: %d, dest: %d, flag: %08x\n", num_dests, src, dest, flags);
            }
        } else if (fn && tag == GCOV_TAG_LINES) {
            print_debug(DEBUG, "GCOV_TAG_LINES:\n");

            gcov_unsigned_t *p = ptr->record;
            unsigned blockno = *p;
            p++;
            unsigned *line_nos = XCNEWVEC (unsigned, length - 1);

            if (blockno >= fn->num_blocks || fn->blocks[blockno].u.line.encoding) {
                print_debug(ERROR, "blockno error. blockno: %d, fn: %d.\n", blockno, fn->num_blocks);
                return ERROR_GCNO_FORMAT;
            }

            print_debug(DEBUG, "block no: %d\n", blockno);
            for (ix = 0; ; ) {
                unsigned lineno = *p;
                p++;

                if (lineno) {
                    if (!ix) {
                        line_nos[ix++] = 0;
                        line_nos[ix++] = src->index;
                    }
                    line_nos[ix++] = lineno;
                    if (lineno >= src->num_lines)
                        src->num_lines = lineno + 1;
                } else {
                    unsigned file_len = *p;
                    p++;
                    if (!file_len)
                        break;
                    int len = file_len*(sizeof(gcov_unsigned_t)/sizeof(char));
                    char *file_name = (char *)malloc(len + 1);
                    memcpy(file_name, p, len);
                    file_name[len] = '\0';
                    src = find_source(file_name);
                    p += file_len;

                    line_nos[ix++] = 0;
                    line_nos[ix++] = src->index;
                    print_debug(DEBUG, "src: %s\n", src->name);
                }
            }
            fn->blocks[blockno].u.line.encoding = line_nos;
            fn->blocks[blockno].u.line.num = ix;

            if (length - 1 < ix) {
                print_debug(ERROR, "lineno error. len: %d, ctr: %d\n", length - 1, ix);
                return ERROR_GCNO_FORMAT;
            }
            for (i = 0; i < ix; i++) {
                print_debug(DEBUG, "[%d]lineno: %d\n", i, line_nos[i]);
            }
        } else if (current_tag && !GCOV_TAG_IS_SUBTAG (current_tag, tag)) {
            fn = NULL;
            current_tag = 0;
        } else {
            print_debug(ERROR, "UNKNOWN TAG: %08x\n", tag);
        }
        ptr = ptr->next;
    }
    {
        source_t *src, *src_p, *src_n;
        for (src_p = NULL, src = sources; src; src_p = src, src = src_n) {
            src_n = src->next;
            src->next = src_p;
        }
        sources =  src_p;
    }

    {
        function_t *fn, *fn_p, *fn_n;
        for (fn_p = old_functions_head, fn = functions; fn != old_functions_head; fn_p = fn, fn = fn_n) {
            unsigned ix;

            fn_n = fn->next;
            fn->next = fn_p;

            for (ix = fn->num_blocks; ix--;) {
                arc_t *arc, *arc_p, *arc_n;

                for (arc_p = NULL, arc = fn->blocks[ix].succ; arc; arc_p = arc, arc = arc_n) {
                    arc_n = arc->succ_next;
                    arc->succ_next = arc_p;
                }
                fn->blocks[ix].succ = arc_p;

                for (arc_p = NULL, arc = fn->blocks[ix].pred; arc; arc_p = arc, arc = arc_n) {
                    arc_n = arc->pred_next;
                    arc->pred_next = arc_p;
                }
                fn->blocks[ix].pred = arc_p;
            }

        }
        functions = fn_p;
    }

    return 0;
}


static int read_count_file (gcov_info *node) {
    record_info *ptr;
    long pos;
    long record_num = node->data_num;
    ptr = node->data;
    int func_id = 0;

    function_t *fn = NULL;
    unsigned tag;
    unsigned length;
    unsigned ix;

    for (pos = 0; pos < record_num; pos++) {
        tag = *(ptr->tag);
        length = *(ptr->length);

        print_debug(DEBUG, "\n[%ld]%08x", pos, tag);

        if (tag == GCOV_TAG_FUNCTION) {
            print_debug(DEBUG, "GCOV_TAG_FUNCTION:\n");
            gcov_unsigned_t *p = ptr->record;
            unsigned ident = *p;

            print_debug(DEBUG, "function id: %d\n", ident);
            struct function_info *fn_n = functions;

            for (fn = fn ? fn->next : NULL; ; fn = fn->next) {
                if (fn);
                else if ((fn = fn_n))
                    fn_n = NULL;
                else {
                    print_debug(ERROR, "unknown function\n");
                    return ERROR_GCDA_FORMAT;
                }
                if (fn->ident == ident)
                    break;
            }

        } else if (tag == GCOV_TAG_FOR_COUNTER (GCOV_COUNTER_ARCS) && fn) {
            print_debug(DEBUG, "GCOV_TAG_COUNTER_BASE:\n");
            gcov_unsigned_t *p = ptr->record;
            gcov_type ctr;

            if (length != GCOV_TAG_COUNTER_LENGTH (fn->num_counts)) {
                print_debug(ERROR, "arc ctr mismatch. length: %d, fn: %d\n", length, fn->num_counts);
                return ERROR_GCDA_FORMAT;
            }

            if (!fn->counts)
                fn->counts = XCNEWVEC(gcov_type, fn->num_counts);

            for (ix = 0; ix != fn->num_counts; ix++)
                fn->counts[ix] = 0;

            for (ix = 0; ix != fn->num_counts; ix++) {
                gcov_read_ctr(&ctr, p);
                fn->counts[ix] += gcov_get_ctr(&ctr);
                p += GCOV_TYPE_LEN;
                print_debug(DEBUG, "arc couter: %lld\n", fn->counts[ix]);
            }

        } else if (tag == GCOV_TAG_OBJECT_SUMMARY) {
            print_debug(DEBUG, "GCOV_TAG_OBJECT_SUMMARY:\n");

            program_summary t_ctr;

            int offset = 0;
            offset++;
            t_ctr.num = gcov_read_unsigned(ptr->record, &offset);
            t_ctr.runs = gcov_read_unsigned(ptr->record, &offset);

            gcov_read_ctr(&t_ctr.sum_all, ptr->record + offset);
            offset += GCOV_TYPE_LEN;

            gcov_read_ctr(&t_ctr.run_max, ptr->record + offset);
            offset += GCOV_TYPE_LEN;

            gcov_read_ctr(&t_ctr.sum_max, ptr->record + offset);

            print_debug(DEBUG, "num:        %ld\n", t_ctr.num);
            print_debug(DEBUG, "runs:       %ld\n", t_ctr.runs);
            print_debug(DEBUG, "sum_all:    %lld\n", gcov_get_ctr(&t_ctr.sum_all));
            print_debug(DEBUG, "run_max:    %lld\n", gcov_get_ctr(&t_ctr.run_max));
            print_debug(DEBUG, "sum_max:    %lld\n", gcov_get_ctr(&t_ctr.sum_max));

        } else if (tag == GCOV_TAG_PROGRAM_SUMMARY) {
            print_debug(DEBUG, "GCOV_TAG_PROGRAM_SUMMARY:\n");

            program_summary t_ctr;

            int offset = 0;
            offset++;
            t_ctr.num = gcov_read_unsigned(ptr->record, &offset);
            t_ctr.runs = gcov_read_unsigned(ptr->record, &offset);

            gcov_read_ctr(&t_ctr.sum_all, ptr->record + offset);
            offset += GCOV_TYPE_LEN;

            gcov_read_ctr(&t_ctr.run_max, ptr->record + offset);
            offset += GCOV_TYPE_LEN;

            gcov_read_ctr(&t_ctr.sum_max, ptr->record + offset);

            print_debug(DEBUG, "num:        %ld\n", t_ctr.num);
            print_debug(DEBUG, "runs:       %ld\n", t_ctr.runs);
            print_debug(DEBUG, "sum_all:    %lld\n", gcov_get_ctr(&t_ctr.sum_all));
            print_debug(DEBUG, "run_max:    %lld\n", gcov_get_ctr(&t_ctr.run_max));
            print_debug(DEBUG, "sum_max:    %lld\n", gcov_get_ctr(&t_ctr.sum_max));

        } else {
            print_debug(ERROR, "UNKNOWN TAG: %08x\n", tag);
        }
        ptr = ptr->next;
    }

    return 0;
}



static int solve_flow_graph (function_t *fn) {
    unsigned ix;
    arc_t *arc;
    gcov_type *count_ptr = fn->counts;
    block_t *blk;
    block_t *valid_blocks = NULL;
    block_t *invalid_blocks = NULL;

    if (fn->num_blocks < 2) {
        print_debug(ERROR, "lacks entry and/or exit blocks\n");
        return ERROR_GCOV_COUNT;
    } else {
        if (fn->blocks[0].num_pred) {
            print_debug(ERROR, "has arcs to entry block\n");
            return ERROR_GCOV_COUNT;
        } else {
            fn->blocks[0].num_pred = ~(unsigned)0;
        }
        if (fn->blocks[fn->num_blocks - 1].num_succ) {
            print_debug(ERROR, "has arcs from exit block\n");
            return ERROR_GCOV_COUNT;
        } else {
            fn->blocks[fn->num_blocks - 1].num_succ = ~(unsigned)0;
        }
    }

    for (ix = 0, blk = fn->blocks; ix != fn->num_blocks; ix++, blk++) {
        block_t const *prev_dst = NULL;
        int out_of_order = 0;
        int non_fake_succ = 0;

        for (arc = blk->succ; arc; arc = arc->succ_next) {
            if (!arc->fake)
                non_fake_succ++;

            if (!arc->on_tree) {
                if (count_ptr)
                    arc->count = *count_ptr++;
                arc->count_valid = 1;
                blk->num_succ--;
                arc->dst->num_pred--;
            }

            if (prev_dst && prev_dst > arc->dst)
                out_of_order = 1;
            prev_dst = arc->dst;
        }

        if (non_fake_succ == 1) {
            for (arc = blk->succ; arc; arc = arc->succ_next)
                if (!arc->fake) {
                    arc->is_unconditional = 1;

                    if (blk->is_call_site && arc->fall_through && arc->dst->pred == arc && !arc->pred_next)
                        arc->dst->is_call_return = 1;
                }
        }

        if (out_of_order) {
            arc_t *start = blk->succ;
            unsigned changes = 1;

            while (changes) {
                arc_t *arc, *arc_p, *arc_n;

                changes = 0;
                for (arc_p = NULL, arc = start; (arc_n = arc->succ_next);) {
                    if (arc->dst > arc_n->dst) {
                        changes = 1;
                        if (arc_p)
                            arc_p->succ_next = arc_n;
                        else
                            start = arc_n;
                        arc->succ_next = arc_n->succ_next;
                        arc_n->succ_next = arc;
                        arc_p = arc_n;
                    } else {
                        arc_p = arc;
                        arc = arc_n;
                    }
                }
            }
            blk->succ = start;
        }

        blk->invalid_chain = 1;
        blk->chain = invalid_blocks;
        invalid_blocks = blk;
    }

    while (invalid_blocks || valid_blocks) {
        while ((blk = invalid_blocks)) {
            gcov_type total = 0;
            const arc_t *arc;

            invalid_blocks = blk->chain;
            blk->invalid_chain = 0;
            if (!blk->num_succ)
                for (arc = blk->succ; arc; arc = arc->succ_next)
                    total += arc->count;
            else if (!blk->num_pred)
                for (arc = blk->pred; arc; arc = arc->pred_next)
                    total += arc->count;
            else
                continue;

            blk->count = total;
            blk->count_valid = 1;
            blk->chain = valid_blocks;
            blk->valid_chain = 1;
            valid_blocks = blk;
        }

        while ((blk = valid_blocks)) {
            gcov_type total;
            arc_t *arc, *inv_arc;

            valid_blocks = blk->chain;
            blk->valid_chain = 0;

            if (blk->num_succ == 1) {
                block_t *dst;

                total = blk->count;
                inv_arc = NULL;
                for (arc = blk->succ; arc; arc = arc->succ_next) {
                    total -= arc->count;
                    if (!arc->count_valid)
                        inv_arc = arc;
                }
                dst = inv_arc->dst;
                inv_arc->count_valid = 1;
                inv_arc->count = total;
                blk->num_succ--;
                dst->num_pred--;
                if (dst->count_valid) {
                    if (dst->num_pred == 1 && !dst->valid_chain) {
                        dst->chain = valid_blocks;
                        dst->valid_chain = 1;
                        valid_blocks = dst;
                    }
                } else {
                    if (!dst->num_pred && !dst->invalid_chain) {
                        dst->chain = invalid_blocks;
                        dst->invalid_chain = 1;
                        invalid_blocks = dst;
                    }
                }
            }

            if (blk->num_pred == 1) {
                block_t *src;

                total = blk->count;
                inv_arc = NULL;
                for (arc = blk->pred; arc; arc = arc->pred_next) {
                    total -= arc->count;
                    if (!arc->count_valid)
                        inv_arc = arc;
                }
                src = inv_arc->src;
                inv_arc->count_valid = 1;
                inv_arc->count = total;
                blk->num_pred--;
                src->num_succ--;
                if (src->count_valid) {
                    if (src->num_succ == 1 && !src->valid_chain) {
                        src->chain = valid_blocks;
                        src->valid_chain = 1;
                        valid_blocks = src;
                    }
                } else {
                    if (!src->num_succ && !src->invalid_chain) {
                        src->chain = invalid_blocks;
                        src->invalid_chain = 1;
                        invalid_blocks = src;
                    }
                }
            }
        }
    }

    #ifdef DEBUG_CHECK_GCOV
        for (ix = 0; ix < fn->num_blocks; ix++) {
            print_debug(DEBUG, "src: '%s'[%d] fn: '%s'[%d], blockno: %d, ctr: %d\n", fn->src->name, fn->src->index, fn->name, fn->ident, ix, fn->blocks[ix].count);
            int i;
            for (i = 2; i < fn->blocks[ix].u.line.num; i++) {
                print_debug(DEBUG, "%d ", fn->blocks[ix].u.line.encoding[i]);
            }
            print_debug(DEBUG, "\n");
        }
    #endif

    for (ix = 0; ix < fn->num_blocks; ix++)
        if (!fn->blocks[ix].count_valid) {
            print_debug(ERROR, "graph is unsolvable for %s\n", fn->name);
            return ERROR_GCOV_COUNT;
        }

    return 0;
}


static int flush_flow(void) {
    function_t *fn;
    function_t *fn_p;
    function_t *old_functions;

    old_functions = functions;
    functions = NULL;


    {/*open gcno*/
        gcov_info *gcno_obj = NULL;
        char *gcno_buf = NULL;
        long gcno_file_size = 0;

        if ((ret_code = read_buf(global_summary.gcno_file, &gcno_file_size, &gcno_buf)) != 0) {
            print_debug(ERROR, "flush_flow::read_buf gcno failed.[%d]\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::read_buf [%s] ok.\n", global_summary.gcno_file);

        if (gcno_file_size == 0) {
            print_debug(ERROR, "flush_flow::[%s] is empty, will not handle.\n", global_summary.gcno_file);
            return ERROR_EMPTY_FILE;
        }

        if ((ret_code = get_gcov_info(gcno_buf, gcno_file_size, &gcno_obj)) != 0) {
            print_debug(ERROR, "flush_flow::get_info gcno failed[%d]\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::get_info [%s] ok.\n", global_summary.gcno_file);

        if ((ret_code = read_graph_file(gcno_obj)) != 0) {
            print_debug(ERROR, "flush_flow::read_graph_file gcno failed[%d]\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::read_graph_file [%s] ok.\n", global_summary.gcno_file);

        if ((ret_code = clean_gcov(&gcno_obj)) != 0) {
            print_debug(ERROR, "flush_flow::clean_gcov gcno failed[%d].\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::clean_gcov [%s] ok.\n", global_summary.gcno_file);
    }

    {/*open gcda*/
        gcov_info *gcda_obj = NULL;
        char *gcda_buf = NULL;
        long gcda_file_size = 0;
        unsigned src_id;

        if ((ret_code = read_buf(global_summary.gcda_file, &gcda_file_size, &gcda_buf)) != 0) {
            print_debug(ERROR, "flush_flow::read_buf gcda failed.[%d]\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::read_buf [%s] ok.\n", global_summary.gcda_file);

        if (gcda_file_size == 0) {
            print_debug(ERROR, "flush_flow::[%s] is empty, will not handle.\n", global_summary.gcda_file);
            return ERROR_EMPTY_FILE;
        }

        if ((ret_code = get_gcov_info(gcda_buf, gcda_file_size, &gcda_obj)) != 0) {
            print_debug(ERROR, "flush_flow::get_info gcda failed[%d]\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::get_info [%s] ok.\n", global_summary.gcda_file);

        if ((ret_code = read_count_file(gcda_obj)) != 0) {
            print_debug(ERROR, "flush_flow::read_count_file gcda failed[%d]\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::read_count_file [%s] ok.\n", global_summary.gcda_file);

        if ((ret_code = clean_gcov(&gcda_obj)) != 0) {
            print_debug(ERROR, "flush_flow::clean_gcov gcda failed[%d].\n", ret_code);
            return ret_code;
        }
        print_debug(INFO, "flush_flow::clean_gcov [%s] ok.\n", global_summary.gcda_file);

    }

    {/*calculate the hit numbers*/
        for (fn_p = NULL, fn = functions; fn; fn_p = fn, fn = fn->next) {
            if ((ret_code = solve_flow_graph(fn)) != 0) {
                print_debug(ERROR, "flush_flow::solve_flow_graph failed[%d].\n", ret_code);
                return ret_code;
            }
        }
        print_debug(INFO, "flush_flow::solve_flow_graph [%s][%s] ok.\n", global_summary.gcno_file, global_summary.gcda_file);

        if (fn_p)
            fn_p->next = old_functions;

    }
    return 0;
}


static int gcc_coverage(void) {
    if ((ret_code = flush_flow()) != 0) {
        print_debug(ERROR, "gcc_coverage::flush_flow failed[%d].", ret_code);
        return ret_code;
    }

    print_debug(INFO, "release structures.\n");
    release_structures();

    return 0;
}



/***************************MAIN***********************************/

void usage(char *exec_name)
{
    printf("###Welcome to use the ats '%s'###\n", exec_name);
    printf("Usage: %s [OPTION]... SOURCEFILES...\n\n", exec_name);
    printf("Merge   gcda: %s -M merged_file.gcda file_a.gcda [file_b.gcda...]\n", exec_name);
    printf("Read counter: %s -R -d file.gcda -n file.gcno\n\n", exec_name);
}


void global_init() {
    print_debug(DEBUG, "gcov_unsigned_t: %d\n", sizeof(gcov_unsigned_t));
    print_debug(DEBUG, "gcov_type:       %d\n", sizeof(gcov_type));
    memset(&global_summary, 0, sizeof(global_summary));

}




/*
    This program is used to read *.gcno & *.gcda files,
    plus the functions of merging *.gcda(from the same source file).
*/

int main(int argc,char** argv) {
    signed int opt;

    if (argc == 1)
        goto show_usage;

    global_init();

    while ((opt = getopt(argc, argv, "d:n:MR")) > 0) {
        switch (opt) {
            case 'd':
                global_summary.gcda_file = optarg;
                break;
            case 'n':
                global_summary.gcno_file = optarg;
                break;
            case 'M':
                flag_merge_gcda = 1;
                break;
            case 'R':
                flag_read_ctr = 1;
                break;
            default:
                goto show_usage;
        }
    }

    if (flag_merge_gcda) {
        int ix;
        print_debug(INFO, "MERGE GCDA.\n");
        if (argc - optind < 2)
            goto show_usage;
        for (ix = optind; ix < argc; ix++)
            print_debug(INFO, "%s ", argv[ix]);
        print_debug(INFO, "\n");
        global_summary.out_file = argv[optind];
        if ((ret_code = merge_gcda(argc, argv)) != 0) {
            print_debug(CRITICAL, "merge gcda failed.[%d]\n", ret_code);
            exit(ret_code);
        }
        goto finish;
    }

    if (flag_read_ctr && global_summary.gcda_file && global_summary.gcno_file) {
        print_debug(INFO, "READ COUNTER.\n");
        if ((ret_code = gcc_coverage()) != 0) {
            print_debug(CRITICAL, "gcc coverage failed[%d].\n", ret_code);
            exit(ret_code);
        } else {
            goto finish;
        }
    }


show_usage:
    usage(argv[0]);
    exit(ERROR_INPUT_OPTION);

finish:
    print_debug(INFO, "Thanks for using!\n");
    return 0;
}



