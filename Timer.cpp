/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// This file targeted Windows (QueryPerformanceCounter/CryptGenRandom/Sleep/
// GetSystemInfo) as well as POSIX. Since the target here is Android (ARM,
// Bionic libc, POSIX-compliant), the Windows branch has been removed
// entirely rather than kept as dead code.

#include "Timer.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>

static const char *prefix[] = { "","Kilo","Mega","Giga","Tera","Peta","Hexa" };

time_t Timer::tickStart;

void Timer::Init() {
tickStart = time(NULL);
}

double Timer::get_tick() {
struct timeval tv;
gettimeofday(&tv, NULL);
return (double)(tv.tv_sec - tickStart) + (double)tv.tv_usec / 1e6;
}

std::string Timer::getSeed(int size) {

std::string ret;
char tmp[3];
unsigned char *buff = (unsigned char *)malloc(size);

// /dev/urandom is available in Android/Termux exactly as on any Linux
// system, so this is unchanged - it was already correct for ARM.
FILE *f = fopen("/dev/urandom","rb");
if(f==NULL) {
printf("Failed to open /dev/urandom %s\n", strerror( errno ));
exit(1);
}
if( fread(buff,1,size,f)!=(size_t)size ) {
printf("Failed to read from /dev/urandom %s\n", strerror( errno ));
exit(1);
}
fclose(f);

for (int i = 0; i < size; i++) {
sprintf(tmp,"%02X",buff[i]);
ret.append(tmp);
}

free(buff);
return ret;

}

uint32_t Timer::getSeed32() {
return ::strtoul(getSeed(4).c_str(),NULL,16);
}

std::string Timer::getResult(char *unit, int nbTry, double t0, double t1) {

char tmp[256];
int pIdx = 0;
double nbCallPerSec = (double)nbTry / (t1 - t0);
while (nbCallPerSec > 1000.0 && pIdx < 5) {
pIdx++;
nbCallPerSec = nbCallPerSec / 1000.0;
}
sprintf(tmp, "%.3f %s%s/sec", nbCallPerSec, prefix[pIdx], unit);
return std::string(tmp);

}

void Timer::printResult(char *unit, int nbTry, double t0, double t1) {

printf("%s\n", getResult(unit, nbTry, t0, t1).c_str());

}

int Timer::getCoreNumber() {
// The POSIX path used to be an unimplemented "TODO: return 1", which
// silently forced every non-Windows build (including this Android build)
// onto a single core no matter how many CPUs the phone actually has.
// sysconf(_SC_NPROCESSORS_ONLN) is the correct, portable POSIX way to ask
// for the number of cores currently online, and it works on Android/Bionic.
long n = sysconf(_SC_NPROCESSORS_ONLN);
return (n > 0) ? (int)n : 1;
}

void Timer::SleepMillis(uint32_t millis) {
usleep(millis*1000);
}
