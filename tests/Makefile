###########################################################################
#
# This should be pretty straightforward.
# Comment out or remove this next, and uncomment appropriate lines below.
CC = YOU MUST EDIT 'Makefile'!!!!

###################### *BSD boxen. ###########################
#MACHINE_FLAGS = -DOST_STARBSD=1 -DWORDS_BIGENDIAN
# On Intel
#MACHINE_FLAGS = -DOST_STARBSD=1
#LIB_FLAGS =
#CC = gcc -pipe
#CC_FLAGS =  -O2

########################### Linux ############################
# Sparc, PPC, etc.
#MACHINE_FLAGS = -DOST_LINUX=1 -DWORDS_BIGENDIAN
# On Intel (Alpha?)
#MACHINE_FLAGS = -DOST_LINUX=1
#LIB_FLAGS =
#CC = gcc -pipe
#CC_FLAGS = -O2
# For debugging & warnings
#CC_FLAGS = -g -Wall -pedantic

##################### Cygwin (Intel) boxen. ##################
#MACHINE_FLAGS = -DOST_CYGWIN=1
#LIB_FLAGS =
#CC = gcc -pipe
#CC_FLAGS = -O2

######################## Compaq Tru64 ########################
#MACHINE_FLAGS = -DOST_TRU64=1
#LIB_FLAGS =
#CC = cc
#CC_FLAGS = -O

######################### Solaris ############################
#MACHINE_FLAGS =  -DOST_SOLARIS=1 -DWORDS_BIGENDIAN
#CC = /opt/compilers/workshop/5.0/SUNWspro/bin/cc
#LIB_FLAGS = -lsocket -lnsl -lresolv
#CC_FLAGS = -fast -O

########################### AIX ##############################
#MACHINE_FLAGS = -DOST_AIX=1 -DWORDS_BIGENDIAN
#LIB_FLAGS =
#CC = /usr/ibmcxx/bin/xlC_r
#CC = /usr/vacpp/bin/xlC_r
#CC_FLAGS = -O

########################## HP-UX #############################
#MACHINE_FLAGS = -DOST_HP=1 -DWORDS_BIGENDIAN
#LIB_FLAGS =
#CC_FLAGS =  -Ae -O
#CC = cc

########################### IRIX #############################
#MACHINE_FLAGS = -DOST_IRIX=1 -DWORDS_BIGENDIAN
#LIB_FLAGS =
# SGI's compiler; use Linux/*BSD examples for gcc
#CC = cc
#CC_FLAGS = -s -O2 -v

########## You shouldn't need to change anything below this line. #########

COMP = $(CC) $(CC_FLAGS)

# Note that we don't just 'rm *.o' - if we didn't make it, we have
# no business rm'ing it.
default:: uidtest find_secret

clean::
	rm -f uidtest.o find_secret.o ost_hash.o md5.o ost.h ost_hash.h md5.h

clobber:: clean
	rm -f uidtest find_secret

vals:
	@echo ${COMP}
	@echo ${MACHINE_FLAGS}
	@echo ${LIB_FLAGS}

find_secret: Makefile find_secret.o ost_hash.o md5.o
	$(COMP) find_secret.o ost_hash.o md5.o -o find_secret $(MACHINE_FLAGS)\
          $(LIB_FLAGS)

find_secret.o: Makefile find_secret.c ost.h ost_hash.h
	$(COMP) -c find_secret.c -o find_secret.o $(MACHINE_FLAGS)

ost_runcmd.o: Makefile uidtest.c
	$(COMP) -c uidtest.c -o uidtest.o $(MACHINE_FLAGS)

ost_hash.h: Makefile md5.h
	cp ../ost_hash.h .

ost.h: Makefile
	cp ../ost.h .

md5.h: Makefile
	cp ../md5.h .

ost_hash.o: Makefile ost_hash.h
	cp ../ost_hash.o .

md5.o: Makefile md5.h
	cp ../md5.o .

uidtest: Makefile uidtest.o
	$(COMP) uidtest.o -o uidtest $(MACHINE_FLAGS) $(LIB_FLAGS)
