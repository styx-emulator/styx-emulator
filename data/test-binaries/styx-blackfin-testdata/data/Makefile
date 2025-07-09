SRCDIR:=src
BINDIR:=bin
ASM_SOURCES := $(wildcard $(SRCDIR)/*.s)
GENERATED_OBJS := $(patsubst $(SRCDIR)/%.s,$(BINDIR)/%.bin,$(ASM_SOURCES))

all: $(GENERATED_OBJS)

$(BINDIR)/%.o: $(SRCDIR)/%.s $(SRCDIR)/testutils.inc
	bfin-elf-as $< -o $@ -I $(SRCDIR)/

$(BINDIR)/%.bin: $(BINDIR)/%.o
	bfin-elf-ld -o $@ -Ttext 0x1000 $<

clean:
	rm -f $(BINDIR)/*
	rm -f $(OBJDIR)/*
