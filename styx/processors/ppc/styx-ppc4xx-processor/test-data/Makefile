PODMAN_RUN:=podman run --rm -it -v $(shell pwd):$(shell pwd):z --userns keep-id --workdir $(shell pwd) powerpc-compiler:latest

TARGETS:=ppc4xx_instruction_test
OBJS:=$(TARGETS:%=%.o)


.PHONY: container clean objdump default

default: ${TARGETS}

clean:
	rm -f ${TARGETS} ${OBJS}
container:
	podman build -t powerpc-compiler .

%.o: %.c
	${PODMAN_RUN} powerpc-linux-gnu-gcc -nostdlib -c $< -Wa,-mregnames -static -mcpu=405 -o $@

${TARGETS}: %: %.o link.ld
	${PODMAN_RUN} powerpc-linux-gnu-ld -nostdlib -T link.ld $< -o $@

%-objdump:
	${PODMAN_RUN} powerpc-linux-gnu-objdump -d $(shell echo $@ | cut -d- -f1)
