CC=gcc
FLAGS=-Wall

ROOT=${shell pwd}

SUBDIRS:= $(ROOT)/config \
	$(ROOT)/hpnetd

export OBJSDIR=$(ROOT)/objs
export BINSDIR=$(ROOT)/bins
export COMMONDIR=$(ROOT)/common
export INCSDIR=$(ROOT)/common

default: dir submake

dir:
	mkdir -p $(OBJSDIR)
	mkdir -p $(BINSDIR)
	mkdir -p $(COMMONDIR)
	@for n in $(SUBDIRS); do cp $$n/*.h $(COMMONDIR)/; done

submake:
	@for n in $(SUBDIRS); do $(MAKE) -C $$n; done

clean:
	@for n in $(SUBDIRS); do $(MAKE) -C $$n clean; done
	rm -rf $(BINSDIR)
	rm -rf $(OBJSDIR)
	rm -rf $(COMMONDIR)
	
