PJBASE=/home/gregor/workspace/projektarbeit/pjproject-2.3

include $(PJBASE)/build.mak

# include the ZRTP specific build.mak. The ZRTP build process creates
# this build.mak. It modifies some variable to include the ZRTP library
# and the ZRTP include path
include $(PJBASE)/third_party/ZRTP4PJ/build/zsrtp/build.mak


CC      = $(PJ_CXX)
LDFLAGS = $(PJ_LDFLAGS)
LDLIBS  = $(PJ_LDLIBS)
CFLAGS  = $(PJ_CFLAGS)
CPPFLAGS= ${CFLAGS}


# If your application is in a file named myapp.cpp or myapp.c
# this is the line you will need to build the binary.
all: mitmphone

mitmPhone185: mitmphone.cpp
		$(CC) -o $@ $< $(CPPFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
		rm -f mitmphone.o mitmphone

	
#$(TARGET):	$(OBJS)
#	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)

#all:	$(TARGET)

#clean:
#	rm -f $(OBJS) $(TARGET)
	
