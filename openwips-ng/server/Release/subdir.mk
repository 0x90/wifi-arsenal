################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../config.c \
../main.c \
../messages.c \
../packet_analysis.c \
../plugins.c \
../users.c 

OBJS += \
./config.o \
./main.o \
./messages.o \
./packet_analysis.o \
./plugins.o \
./users.o 

C_DEPS += \
./config.d \
./main.d \
./messages.d \
./packet_analysis.d \
./plugins.d \
./users.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


