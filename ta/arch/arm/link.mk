link-script$(sm) = $(ta-dev-kit-dir$(sm))/src/ta.ld.S
link-script-pp$(sm) = $(link-out-dir$(sm))/ta.lds
link-script-dep$(sm) = $(link-out-dir$(sm))/.ta.ld.d

SIGN_ENC ?= $(ta-dev-kit-dir$(sm))/scripts/sign_encrypt.py
TA_SIGN_KEY ?= $(ta-dev-kit-dir$(sm))/keys/default_ta.pem

ifeq ($(CFG_ENCRYPT_TA),y)
# Default TA encryption key is a dummy key derived from default
# hardware unique key (an array of 16 zero bytes) to demonstrate
# usage of REE-FS TAs encryption feature.
#
# Note that a user of this TA encryption feature needs to provide
# encryption key and its handling corresponding to their security
# requirements.
TA_ENC_KEY ?= 'b64d239b1f3c7d3b06506229cd8ff7c8af2bb4db2168621ac62c84948468c4f4'
endif

all: $(link-out-dir$(sm))/$(user-ta-uuid).dmp \
	$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf \
	$(link-out-dir$(sm))/$(user-ta-uuid).ta
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).elf
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).dmp
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).map
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).ta
cleanfiles += $(link-script-pp$(sm)) $(link-script-dep$(sm))

link-ldflags  = -e__ta_entry -pie
link-ldflags += -T $(link-script-pp$(sm))
link-ldflags += -Map=$(link-out-dir$(sm))/$(user-ta-uuid).map
link-ldflags += --sort-section=alignment
link-ldflags += -z max-page-size=4096 # OP-TEE always uses 4K alignment
link-ldflags += --as-needed # Do not add dependency on unused shlib
link-ldflags += $(link-ldflags$(sm))

# Symbols from the TA main executable that should be exported (added to the
# .dynsym table of the TA)
# These symbols are referenced by libutee. When the main TA executable is
# linked against libutee.a, but other shared libraries ultimately reference
# these symbols (that is, a shared library used by the TA links against either
# libutee.a or libutee.so), symbols need to be present in the TA .dynsym, but
# the linker would not automatically add them since at that time it finds all
# the symbols in libutee.a. Example of such a case: a TA with C++ code and
# CFG_ULIBS_SHARED=y.
dynsym-symbols += ta_head ta_heap ta_heap_size ta_num_props ta_props
dynsym-symbols += tahead_get_trace_level trace_ext_prefix trace_level trace_level
dynsym-symbols += TA_CloseSessionEntryPoint TA_CreateEntryPoint TA_DestroyEntryPoint
dynsym-symbols += TA_InvokeCommandEntryPoint TA_OpenSessionEntryPoint
# __elf_phdr_info and __ftrace_info are always resolved dynamically by ldelf
dynsym-symbols += __elf_phdr_info
ifeq ($(CFG_FTRACE_SUPPORT),y)
dynsym-symbols += __ftrace_info
endif

$(link-out-dir$(sm))/dyn_list:
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)mkdir -p $(dir $@)
	$(q)echo "{ $(foreach s,$(dynsym-symbols),$(s); )};" >$@
link-ldflags += --dynamic-list $(link-out-dir$(sm))/dyn_list
dynlistdep = $(link-out-dir$(sm))/dyn_list
cleanfiles += $(link-out-dir$(sm))/dyn_list

link-ldadd  = $(user-ta-ldadd) $(addprefix -L,$(libdirs))
link-ldadd += --start-group
ifeq (,$(filter %.cpp,$(srcs)))
link-ldadd += $(addprefix -l,$(libnames))
else
link-ldflags += --eh-frame-hdr
link-ldadd += $(libstdc++$(sm)) $(libgcc_eh$(sm))
# With C++, libutee must be linked statically or exception handling cannot work
link-ldadd += -l:libutee.a
link-ldadd += $(addprefix -l,$(filter-out utee,$(libnames)))
endif
link-ldadd += --end-group

ldargs-$(user-ta-uuid).elf := $(link-ldflags) $(objs) $(link-ldadd)


link-script-cppflags-$(sm) := \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinc$(sm)) $(CPPFLAGS) \
		$(addprefix -I,$(incdirs$(sm)) $(link-out-dir$(sm))) \
		$(cppflags$(sm)))

-include $(link-script-dep$(sm))

link-script-pp-makefiles$(sm) = $(filter-out %.d %.cmd,$(MAKEFILE_LIST))

define gen-link-t
$(link-script-pp$(sm)): $(link-script$(sm)) $(conf-file) $(link-script-pp-makefiles$(sm))
	@$(cmd-echo-silent) '  CPP     $$@'
	$(q)mkdir -p $$(dir $$@)
	$(q)$(CPP$(sm)) -P -MT $$@ -MD -MF $(link-script-dep$(sm)) \
		$(link-script-cppflags-$(sm)) $$< -o $$@

$(link-out-dir$(sm))/$(user-ta-uuid).elf: $(objs) $(libdeps) \
					  $(link-script-pp$(sm)) \
					  $(dynlistdep) \
					  $(additional-link-deps)
	@$(cmd-echo-silent) '  LD      $$@'
	$(q)$(LD$(sm)) $(ldargs-$(user-ta-uuid).elf) -o $$@

$(link-out-dir$(sm))/$(user-ta-uuid).dmp: \
			$(link-out-dir$(sm))/$(user-ta-uuid).elf
	@$(cmd-echo-silent) '  OBJDUMP $$@'
	$(q)$(OBJDUMP$(sm)) -l -x -d $$< > $$@

$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf: \
			$(link-out-dir$(sm))/$(user-ta-uuid).elf
	@$(cmd-echo-silent) '  OBJCOPY $$@'
	$(q)$(OBJCOPY$(sm)) --strip-unneeded $$< $$@

cmd-echo$(user-ta-uuid) := SIGN   #
ifeq ($(CFG_ENCRYPT_TA),y)
crypt-args$(user-ta-uuid) := --enc-key $(TA_ENC_KEY)
cmd-echo$(user-ta-uuid) := SIGNENC
endif
$(link-out-dir$(sm))/$(user-ta-uuid).ta: \
			$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf \
			$(TA_SIGN_KEY)
	@$(cmd-echo-silent) '  $$(cmd-echo$(user-ta-uuid)) $$@'
	$(q)$(SIGN_ENC) --key $(TA_SIGN_KEY) $$(crypt-args$(user-ta-uuid)) \
		--uuid $(user-ta-uuid) --ta-version $(user-ta-version) \
		--in $$< --out $$@
endef

$(eval $(call gen-link-t))

additional-link-deps :=
