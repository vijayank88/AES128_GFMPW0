.SUFFIXES:

PATTERN = aes_wb

all:  ${PATTERN:=.vcd}

%.vvp: %_tb.v
	iverilog  -I ../../../verilog/ \
	$< -o $@

%.vcd: %.vvp
	vvp $<

clean:
	rm -f *.vvp *.vcd *.log

.PHONY: clean all
