CC=g++

CFLAG=
TARGET=yamcov
SRCS=$(wildcard *.c) $(wildcard *.cc) $(wildcard *.cpp)
OBJ:=$(patsubst %.cpp, %.o, $(SRCS))

LOCAL_INC+=inc/

%.o:%.cpp
	$(CC) -c -I$(LOCAL_INC) $(CFLAG) $< -o $@

$(TARGET):$(OBJ)
	$(CC) -pthread $(CFLAG) $(OBJ) -o $@ 

.PHONY:clean
clean:
	-rm -f $(OBJ)
	-rm -f $(TARGET)

distclean:
	-rm -f $(OBJ)
	-rm -f $(TARGET)
