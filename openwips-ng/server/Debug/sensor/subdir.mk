################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../sensor/command_parse.c \
../sensor/packet_assembly.c \
../sensor/rpcap_server.c \
../sensor/sensor.c 

OBJS += \
./sensor/command_parse.o \
./sensor/packet_assembly.o \
./sensor/rpcap_server.o \
./sensor/sensor.o 

C_DEPS += \
./sensor/command_parse.d \
./sensor/packet_assembly.d \
./sensor/rpcap_server.d \
./sensor/sensor.d 


# Each subdirectory must supply rules for building sources it contributes
sensor/%.o: ../sensor/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -DDEBUG -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


