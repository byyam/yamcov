#!/usr/bin/env python

'''
Description: Function test yamcov. Merge gcda files.
Author: YamCheung
E-mail: yanzhang.scut@gmail.com
'''

import os, sys
import inspect

THIS_DIR = os.path.abspath(os.path.dirname(inspect.stack()[0][1]))
TMP_DIR = os.path.join(THIS_DIR, 'tmp')
SRC_DIR = os.path.join(THIS_DIR, '../')

test_c_str = '''
#include <stdio.h>
#include <getopt.h>

void function_one()
{
    printf("this function should never be called.");
}

void sum(int a, int b)
{
    int c;
    c = a + b;
    printf("running sum function.");
}

void multi(int a, int b)
{
    int c;
    c = a * b;
    printf("running multi function.");
}

int main(int argc,char *argv[])
{
    int opt;
    int i = 10;
    int j = 30;
    while((opt = getopt(argc, argv, "abh")) != -1) {
        switch(opt) {
            case 'h':
                printf("help...");
                break;
            case 'a':
                sum(i, j);
                break;
            case 'b':
                multi(i, j);
                break;
            default:
                printf("invalid...");
        }
    }
    return 0;
}
''';

def test_prepare_data():
    os.system('rm -rf %s' % (TMP_DIR))
    os.system('mkdir -p %s' % (TMP_DIR))
    fd = file('%s' % os.path.join(TMP_DIR, 'test_merge_gcda.c'), 'w')
    fd.write(test_c_str)
    fd.close()

    os.system('cd %s; make clean; make' % (SRC_DIR))


def test_merge_gcda():
    os.system('cd %s; gcc -fprofile-arcs -ftest-coverage test_merge_gcda.c -o test_merge_gcda' % (TMP_DIR))
    os.system('cd %s; ./test_merge_gcda -a' % (TMP_DIR))
    os.system('cd %s; ./test_merge_gcda -b' % (TMP_DIR))
    os.system('cd %s; gcov test_merge_gcda.c' % (TMP_DIR))
    os.system('cd %s; mv test_merge_gcda.c.gcov test_merge_gcda.c.gcov.running' % (TMP_DIR))
    os.system('cd %s; rm -f test_merge_gcda.gcda' % (TMP_DIR))

    os.system('cd %s; ./test_merge_gcda -b' % (TMP_DIR))
    os.system('cd %s; gcov test_merge_gcda.c' % (TMP_DIR))
    os.system('cd %s; mv test_merge_gcda.gcda test_merge_gcda.b.gcda' % (TMP_DIR))

    os.system('cd %s; ./test_merge_gcda -a' % (TMP_DIR))
    os.system('cd %s; gcov test_merge_gcda.c' % (TMP_DIR))
    os.system('cd %s; cp test_merge_gcda.gcda test_merge_gcda.a.gcda' % (TMP_DIR))

    os.system('cd %s; ./yamcov -M %s %s %s' % (SRC_DIR, os.path.join(TMP_DIR, 'test_merge_gcda.gcda'), os.path.join(TMP_DIR, 'test_merge_gcda.gcda'), os.path.join(TMP_DIR, 'test_merge_gcda.b.gcda')))
    os.system('cd %s; gcov test_merge_gcda.c' % (TMP_DIR))

    diff_result = os.system('cd %s; diff test_merge_gcda.c.gcov test_merge_gcda.c.gcov.running' % (TMP_DIR))
    print '================================='
    print 'The test result is:'
    if diff_result:
        print 'failed!'
    else:
        print 'success!'

def test_clean_up():
    os.system('rm -rf %s' % (TMP_DIR))
    os.system('cd %s; make clean' % (SRC_DIR))


def main(args):
    test_prepare_data()
    test_merge_gcda()
    test_clean_up()

if __name__ == '__main__':
    main(sys.argv[1:])
