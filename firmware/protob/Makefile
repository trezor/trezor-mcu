ifneq ($(V),1)
Q := @
endif

all: messages.pb.c types.pb.c messages_map.h

PYTHON ?= python

%.pb.c: %.pb %.options
	@printf "  NANOPB  $@\n"
	$(Q)$(PYTHON) ../../vendor/nanopb/generator/nanopb_generator.py $< -L '#include "%s"' -T

%.pb: %.proto
	@printf "  PROTOC  $@\n"
	$(Q)protoc -I/usr/include -I. $< -o $@

%_pb2.py: %.proto
	@printf "  PROTOC  $@\n"
	$(Q)protoc -I/usr/include -I. $< --python_out=.

messages_map.h: messages_map.py messages_pb2.py types_pb2.py
	@printf "  PYTHON  $<\n"
	$(Q)$(PYTHON) $< | grep -v -e MessageType_Lisk -e MessageType_Stellar > $@

clean:
	rm -f *.pb *.o *.d *.pb.c *.pb.h *_pb2.py messages_map.h
