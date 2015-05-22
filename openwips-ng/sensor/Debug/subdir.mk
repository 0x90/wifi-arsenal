################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../client.c \
../command_parse.c \
../global_var.c \
../main.c \
../packet_capture.c \
../rpcap.c \
../structures.c 

OBJS += \
./client.o \
./command_parse.o \
./global_var.o \
./main.o \
./packet_capture.o \
./rpcap.o \
./structures.o 

C_DEPS += \
./client.d \
./command_parse.d \
./global_var.d \
./main.d \
./packet_capture.d \
./rpcap.d \
./structures.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -DDEBUG -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


