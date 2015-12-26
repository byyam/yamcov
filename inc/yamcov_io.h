/****************************************************
 *
 * This is a tool help to research gcda/gcno in gcc.
 * Author:YamCheung
 * email:yanzhang.scut@gmail.com
 *
 * **************************************************
 * */
#ifndef YAMCOV_IO_H
#define YAMCOV_IO_H


/*type defination about gcov.*/
typedef unsigned gcov_unsigned_t;
typedef unsigned long long gcov_type;


struct function_info;
struct block_info;
struct source_info;

typedef struct arc_info
{
  struct block_info *src;
  struct block_info *dst;

  gcov_type count;
  gcov_type cs_count;

  unsigned int count_valid : 1;
  unsigned int on_tree : 1;
  unsigned int fake : 1;
  unsigned int fall_through : 1;

  unsigned int is_call_non_return : 1;
  unsigned int is_nonlocal_return : 1;
  unsigned int is_unconditional : 1;

  unsigned int cycle : 1;

  struct arc_info *line_next;
  struct arc_info *succ_next;
  struct arc_info *pred_next;
} arc_t;


typedef struct block_info
{
  arc_t *succ;
  arc_t *pred;

  gcov_type num_succ;
  gcov_type num_pred;

  gcov_type count;
  unsigned flags : 13;
  unsigned count_valid : 1;
  unsigned valid_chain : 1;
  unsigned invalid_chain : 1;

  unsigned is_call_site : 1;
  unsigned is_call_return : 1;

  unsigned is_nonlocal_return : 1;

  union
  {
    struct
    {
      unsigned *encoding;
      unsigned num;
    } line;
    struct
    {
      arc_t *arc;
      unsigned ident;
    } cycle;
  } u;

  struct block_info *chain;

} block_t;

typedef struct function_info
{
  char *name;
  unsigned ident;
  unsigned checksum;

  block_t *blocks;
  unsigned num_blocks;
  unsigned blocks_executed;

  gcov_type *counts;
  unsigned num_counts;

  unsigned line;
  struct source_info *src;
  struct function_info *line_next;
  struct function_info *next;
} function_t;

typedef struct coverage_info
{
  int lines;
  int lines_executed;

  int branches;
  int branches_executed;
  int branches_taken;

  int calls;
  int calls_executed;

  char *name;
} coverage_t;


typedef struct line_info
{
  gcov_type count;
  union
  {
    arc_t *branches;
    block_t *blocks;
  } u;
  unsigned exists : 1;
} line_t;


typedef struct source_info
{
  char *name;
  unsigned index;
  time_t file_time;

  line_t *lines;
  unsigned num_lines;

  coverage_t coverage;
  function_t *functions;
  struct source_info *next;
} source_t;


typedef struct {
    gcov_unsigned_t num;
    gcov_unsigned_t runs;
    gcov_type sum_all;
    gcov_type run_max;
    gcov_type sum_max;
}program_summary;

typedef struct {
    gcov_unsigned_t *func_id;
    gcov_unsigned_t *checksum;
    gcov_unsigned_t *func_len;
    gcov_unsigned_t *func;
    gcov_unsigned_t *path_len;
    gcov_unsigned_t *path;
    gcov_unsigned_t *lineno;
}function_block;

typedef struct {
    gcov_unsigned_t *bb_id;
    gcov_unsigned_t *bb_encoding;
    gcov_unsigned_t *linker;
    gcov_unsigned_t *path_len;
    gcov_unsigned_t *path;
    gcov_unsigned_t *line_no;
}line_block;

typedef struct record_node {
    gcov_unsigned_t *tag;
    gcov_unsigned_t *length;
    gcov_unsigned_t *record;
    struct record_node *next;
}record_info;

typedef struct gcov_node{
    char *buf;
    gcov_unsigned_t *header_buf;
    record_info *data;
    long data_num;
    long file_size;
    struct gcov_node *next;
}gcov_info;



/*for accumulate the offset in binary.*/
#define GCOV_TYPE_LEN                   sizeof(gcov_type)/sizeof(gcov_unsigned_t)

/*magic number for TAGs.*/
#define GCOV_TAG_FUNCTION               ((gcov_unsigned_t)0x01000000)
#define GCOV_TAG_FUNCTION_LENGTH        (2)
#define GCOV_TAG_BLOCKS                 ((gcov_unsigned_t)0x01410000)
#define GCOV_TAG_BLOCKS_LENGTH(NUM)     (NUM)
#define GCOV_TAG_BLOCKS_NUM(LENGTH)     (LENGTH)
#define GCOV_TAG_ARCS                   ((gcov_unsigned_t)0x01430000)
#define GCOV_TAG_ARCS_LENGTH(NUM)       (1 + (NUM) * 2)
#define GCOV_TAG_ARCS_NUM(LENGTH)       (((LENGTH) - 1) / 2)
#define GCOV_TAG_LINES                  ((gcov_unsigned_t)0x01450000)
#define GCOV_TAG_COUNTER_BASE           ((gcov_unsigned_t)0x01a10000)
#define GCOV_TAG_COUNTER_LENGTH(NUM)    ((NUM) * 2)
#define GCOV_TAG_COUNTER_NUM(LENGTH)    ((LENGTH) / 2)
#define GCOV_TAG_OBJECT_SUMMARY         ((gcov_unsigned_t)0xa1000000)
#define GCOV_TAG_PROGRAM_SUMMARY        ((gcov_unsigned_t)0xa3000000)

/*magic: 1, version: 1, stamp: 1*/
#define GCDA_HEADER_LENGTH              (3)
#define GCDA_RECORD_TAG_LENGTH          (1)
#define GCDA_RECORD_LENGTH_LENGTH       (1)
#define GCDA_TAG_PROGRAM_LENGTH         ((gcov_unsigned_t)0x00000009)

#define GCOV_TAG_MASK(TAG)              (((TAG) - 1) ^ (TAG))

/* return nonzero if SUB is an immediate subtag of TAG.  */
#define GCOV_TAG_IS_SUBTAG(TAG,SUB)                \
    (GCOV_TAG_MASK (TAG) >> 8 == GCOV_TAG_MASK (SUB)     \
     && !(((SUB) ^ (TAG)) & ~GCOV_TAG_MASK(TAG)))

#define GCOV_TAG_FOR_COUNTER(COUNT)                \
    (GCOV_TAG_COUNTER_BASE + ((gcov_unsigned_t)(COUNT) << 17))

#define GCOV_COUNTER_ARCS               (0)

/* arc flags.  */
#define GCOV_ARC_ON_TREE                (1 << 0)
#define GCOV_ARC_FAKE                   (1 << 1)
#define GCOV_ARC_FALLTHROUGH            (1 << 2)


#endif
