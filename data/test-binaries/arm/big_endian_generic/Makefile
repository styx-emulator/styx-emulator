SRCDIR:=src
BINDIR:=elf
ASM_SOURCES := $(wildcard $(SRCDIR)/*.s)
GENERATED_OBJS := $(patsubst $(SRCDIR)/%.s,$(BINDIR)/%.elf,$(ASM_SOURCES))

all: $(GENERATED_OBJS)

$(BINDIR)/%.o: $(SRCDIR)/%.s $(SRCDIR)/testutils.inc
	armeb-none-eabi-as $< -EB -o $@ -I $(SRCDIR)/

$(BINDIR)/%.elf: $(BINDIR)/%.o
	armeb-none-eabi-ld -EB -o $@ -Ttext 0x1000 $<


clean:
	rm -f $(BINDIR)/*
	rm -f $(OBJDIR)/*
