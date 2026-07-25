# Makefile -- сборка C-части на Linux и macOS.
#
# На Windows пользуйтесь build.ps1: он находит MSVC сам.
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# Здесь же:
#   make            собрать библиотеку и утилиты
#   make test       собрать и прогнать векторы раздела 8 + быстрый набор Python
#   make bench      замер циклов на байт
#   make clean

CC      ?= cc
CFLAGS  ?= -O3 -std=c11 -Wall -Wextra -DNDEBUG
SRCDIR   = c
BUILD    = build

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LIB = libdedalyan.dylib
else
  LIB = libdedalyan.so
endif

CORE = $(SRCDIR)/dedalyan.c $(SRCDIR)/kernels.c
HDRS = $(SRCDIR)/dedalyan.h $(SRCDIR)/kernels.h

.PHONY: all test bench clean

all: $(BUILD)/$(LIB) $(BUILD)/test_vectors $(BUILD)/bench

$(BUILD):
	mkdir -p $(BUILD)

# Разделяемая библиотека для ctypes. Имя обязано совпадать с тем, что ищет
# dedalyan_c.py, иначе Python молча уйдёт на медленный путь.
$(BUILD)/$(LIB): $(CORE) $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -DDEDALYAN_BUILD_DLL $(CORE) -o $@

$(BUILD)/test_vectors: $(CORE) $(SRCDIR)/test_vectors.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRCDIR) $(CORE) $(SRCDIR)/test_vectors.c -o $@

$(BUILD)/bench: $(CORE) $(SRCDIR)/bench.c $(HDRS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRCDIR) $(CORE) $(SRCDIR)/bench.c -o $@

test: all
	$(BUILD)/test_vectors
	python3 tests/run_all.py --profile quick

bench: $(BUILD)/bench
	$(BUILD)/bench 32

clean:
	rm -rf $(BUILD)
	find . -name __pycache__ -type d -exec rm -rf {} +
