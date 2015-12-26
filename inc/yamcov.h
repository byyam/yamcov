/****************************************************
 *
 * This is a tool help to research gcda/gcno in gcc.
 * Author:YamCheung
 * email:yanzhang.scut@gmail.com
 *
 * **************************************************
 * */
#ifndef YAMCOV_H
#define YAMCOV_H


typedef struct global_info{
    char *gcda_file;
    char *gcno_file;
    char *out_file;
}global_t;

/*length limits for name of files.*/
#define DB_COLLECTION_NAME_LEN          (1024)
#define SOURCE_PATH_LENGTH              (2048)
#define GCOV_PATH_LENGTH                (2048)


/*
src id | function no | bb no | line no
use char to show ASCII(4 bits)
*/
#define OBJECT_USE                      (4)
#define OBJECT_LEN                      (sizeof(unsigned) * 2 / sizeof(char))
#define OBJECT_ID_LEN                   (OBJECT_LEN * OBJECT_USE + 1)



/*fixed flag*/
static int flag_all_blocks = 0;
static int flag_function_summary = 0;
static int flag_branches = 1;
static int flag_merge_gcda = 0;
static int flag_read_ctr = 0;

/*variable flag*/


/*for debug, hide if needed.*/
#define DEBUG_READ_FILE
#define DEBUG_MERGE_GCDA

typedef enum {
    ERROR_DB_CONN_REJECT = 1,
    ERROR_DB_INSERT_REJECT,
    ERROR_DB_FIND_REJECT,
    ERROR_DB_COUNT_REJECT,
    ERROR_DB_NOT_FOUND,
    ERROR_DB_DATA,
    ERROR_INPUT_OPTION,
    ERROR_NAME_LEN,
    ERROR_OPEN_FILE,
    ERROR_READ_FILE,
    ERROR_WRITE_FILE,
    ERROR_CLOSE_FILE,
    ERROR_EMPTY_FILE,
    ERROR_MEMORY_ALLOCATE,
    ERROR_GCNO_FORMAT,
    ERROR_GCDA_FORMAT,
    ERROR_GCOV_COUNT,
    ERROR_SOURCE_ID_LEN,
    ERROR_FUNCTION_NO_LEN,
    ERROR_BB_NO_LEN,
    ERROR_EXIT_TIMER,
}GCOV_ERROR_CODE;


/*
    This part is for debug info.
*/

typedef enum {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
}DEBUG_SWITCH;

DEBUG_SWITCH g_debug_level = DEBUG;

#define print_debug(level, format, ...) \
    do { \
        if (level >= g_debug_level) \
            printf(""format"", ##__VA_ARGS__); \
    } while(0)



#endif
