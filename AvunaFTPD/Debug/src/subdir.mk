################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/accept.c \
../src/collection.c \
../src/config.c \
../src/log.c \
../src/main.c \
../src/streams.c \
../src/tls.c \
../src/util.c \
../src/work.c \
../src/xstring.c 

OBJS += \
./src/accept.o \
./src/collection.o \
./src/config.o \
./src/log.o \
./src/main.o \
./src/streams.o \
./src/tls.o \
./src/util.o \
./src/work.o \
./src/xstring.o 

C_DEPS += \
./src/accept.d \
./src/collection.d \
./src/config.d \
./src/log.d \
./src/main.d \
./src/streams.d \
./src/tls.d \
./src/util.d \
./src/work.d \
./src/xstring.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	$(CC) $(CFLAGS) -std=gnu11 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


