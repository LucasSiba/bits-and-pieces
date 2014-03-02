# Copyright (c) 2010 Sophos Group.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

# Find the relative path to the component directory and to the top of the hierarchy

COM.dir := $(patsubst %/,%,$(dir $(word $(words $(MAKEFILE_LIST)), $(MAKEFILE_LIST))))
TOP.dir = $(COM.dir)/..

# List of the libraries in linker order.
# This is used by both the package GNUmakefiles and the top level GNUmakefile
remove_to = $(if $(filter $(1),$(2)),$(call remove_to,$(1),$(wordlist 2,$(words $(2)),$(2))),$(2))
ALL_LIBRARIES    =
LIB_DEPENDENCIES = $(call remove_to,$(LIBRARIES),$(ALL_LIBRARIES))

include $(TOP.dir)/mak/mak-common.mak

IFLAGS     += -I$(TOP.dir)/libsxe/$(DST.dir)/include
LINK_FLAGS +=   $(TOP.dir)/libsxe/$(DST.dir)/libsxe$(EXT.lib)

