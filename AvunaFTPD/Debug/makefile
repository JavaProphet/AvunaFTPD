-include ../makefile.init

RM := rm -rf
CP := cp -r
CHMOD := chmod
MKDIR := mkdir

# All of the sources participating in the build are defined here
-include sources.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: AvunaFTPD

debug: CFLAGS += -DDEBUG
debug: AvunaFTPD

# Tool invocations
AvunaFTPD: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) $(CFLAGS) -o "AvunaFTPD" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) AvunaFTPD
	-@echo ' '

install:
	-$(CP) AvunaFTPD /usr/bin/AvunaFTPD
	-$(CHMOD) 755 /usr/bin/AvunaFTPD
	-$(MKDIR) -p /etc/avuna/ftpd/
	-$(CP) ../main.cfg /etc/avuna/ftpd/main.cfg
	-$(CP) ../users.cfg /etc/avuna/ftpd/users.cfg

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
