SRCDIR:=src
BINDIR:=bin
ASM_SOURCES := $(wildcard $(SRCDIR)/*.s)
GENERATED_OBJS := $(patsubst $(SRCDIR)/%.s,$(BINDIR)/%.bin,$(ASM_SOURCES))

all: $(GENERATED_OBJS)

$(BINDIR)/%.o: $(SRCDIR)/%.s $(SRCDIR)/testutils.inc
	aarch64-none-elf-as $< -o $@ -I $(SRCDIR)/

$(BINDIR)/%.elf: $(BINDIR)/%.o
	aarch64-none-elf-ld -o $@ -Ttext 0x1000 $<

$(BINDIR)/%.bin: $(BINDIR)/%.elf
	aarch64-none-elf-objcopy -Obinary $< $@

clean:
	rm -f $(BINDIR)/*
	rm -f $(OBJDIR)/*
