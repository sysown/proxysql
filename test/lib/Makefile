DEPS_PATH=../../deps
LIB_DIR=../../lib
INCLUDE_DIR=../../include

MONGOOSE_DIR=$(DEPS_PATH)/mongoose/mongoose

IDIRS=-I$(INCLUDE_DIR) -I$(MONGOOSE_DIR)

ODIR=obj
BINDIR=bin

MYCFLAGS=$(IDIRS) $(OPTZ) $(DEBUG) -Wall
MYCPPFLAGS=-std=c++11 $(MYCFLAGS)
MYLDFLAGS=-lssl -lcrypto -lpthread
$(ODIR):
	mkdir $(ODIR)

$(BINDIR):
	mkdir $(BINDIR)

$(ODIR)/%.oo2: %.cpp
	$(CXX) -fPIC -c -o $@ $< $(MYCPPFLAGS) $(CPPFLAGS) -DMG_ENABLE_SSL -DMD5_HEADER_DEFINED

http_client_test: $(ODIR) $(BINDIR) $(ODIR)/http_client_test.oo2
	$(CXX) -o $(BINDIR)/http_client_test $(ODIR)/http_client_test.oo2 $(LIB_DIR)/obj/http_client.oo2 $(MONGOOSE_DIR)/mongoose.o $(MYLDFLAGS)
.PHONY: http_client_test

clean:
	rm -rf $(ODIR) $(BINDIR)