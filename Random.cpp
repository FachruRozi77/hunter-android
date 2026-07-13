#include "Point.h"

Point::Point() {
}

Point::Point(const Point &p) {
x.Set((Int *)&p.x);
y.Set((Int *)&p.y);
z.Set((Int *)&p.z);
}

Point::Point(Int *cx,Int *cy,Int *cz) {
x.Set(cx);
y.Set(cy);
z.Set(cz);
}

Point::Point(Int *cx, Int *cz) {
x.Set(cx);
z.Set(cz);
}

void Point::Clear() {
x.SetInt32(0);
y.SetInt32(0);
z.SetInt32(0);
}

void Point::Set(Int *cx, Int *cy,Int *cz) {
x.Set(cx);
y.Set(cy);
z.Set(cz);
}

Point::~Point() {
}

void Point::Set(Point &p) {
x.Set(&p.x);
y.Set(&p.y);
z.Set(&p.z);
}

bool Point::isZero() {
return x.IsZero() && y.IsZero();
}

void Point::Reduce() {

Int i(&z);
i.ModInv();
x.ModMul(&x,&i);
y.ModMul(&y,&i);
z.SetInt32(1);

}

bool Point::equals(Point &p) {
return x.IsEqual(&p.x) && y.IsEqual(&p.y) && z.IsEqual(&p.z);
}
'''

with open('/mnt/agents/output/Point.cpp', 'w') as f:
    f.write(point_cpp_content)

print("Point.cpp written successfully")

# Random.h
random_h_content = r'''/*
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

#ifndef RANDOM_H
#define RANDOM_H

double rnd();
unsigned long rndl();
void rseed(unsigned long seed);

#endif
'''

with open('/mnt/agents/output/Random.h', 'w') as f:
    f.write(random_h_content)

print("Random.h written successfully")

# Random.cpp
random_cpp_content = r'''/*
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

#include "Random.h"

#define RK_STATE_LEN 624

/* State of the RNG */
typedef struct rk_state_
{
unsigned long key[RK_STATE_LEN];
int pos;
} rk_state;

rk_state localState;

/* Maximum generated random value */
#define RK_MAX 0xFFFFFFFFUL

void rk_seed(unsigned long seed, rk_state *state)
{
int pos;
seed &= 0xffffffffUL;

/* Knuth's PRNG as used in the Mersenne Twister reference implementation */
for (pos=0; pos<RK_STATE_LEN; pos++)
{
state->key[pos] = seed;
seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 1) & 0xffffffffUL;
}

state->pos = RK_STATE_LEN;
}

/* Magic Mersenne Twister constants */
#define N 624
#define M 397
#define MATRIX_A 0x9908b0dfUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7fffffffUL

/* Slightly optimised reference implementation of the Mersenne Twister */
inline unsigned long rk_random(rk_state *state)
{
unsigned long y;

if (state->pos == RK_STATE_LEN)
{
int i;

for (i=0;i<N-M;i++)
{
y = (state->key[i] & UPPER_MASK) | (state->key[i+1] & LOWER_MASK);
state->key[i] = state->key[i+M] ^ (y>>1) ^ (-(y & 1) & MATRIX_A);
}
for (;i<N-1;i++)
{
y = (state->key[i] & UPPER_MASK) | (state->key[i+1] & LOWER_MASK);
state->key[i] = state->key[i+(M-N)] ^ (y>>1) ^ (-(y & 1) & MATRIX_A);
}
y = (state->key[N-1] & UPPER_MASK) | (state->key[0] & LOWER_MASK);
state->key[N-1] = state->key[M-1] ^ (y>>1) ^ (-(y & 1) & MATRIX_A);

state->pos = 0;
}

y = state->key[state->pos++];

/* Tempering */
y ^= (y >> 11);
y ^= (y << 7) & 0x9d2c5680UL;
y ^= (y << 15) & 0xefc60000UL;
y ^= (y >> 18);

return y;
}

inline double rk_double(rk_state *state)
{
/* shifts : 67108864 = 0x4000000, 9007199254740992 = 0x20000000000000 */
long a = rk_random(state) >> 5, b = rk_random(state) >> 6;
return (a * 67108864.0 + b) / 9007199254740992.0;
}

// Initialise the random generator with the specified seed
void rseed(unsigned long seed) {
rk_seed(seed,&localState);
//srand(seed);
}

unsigned long rndl() {
return rk_random(&localState);
}

// Returns a uniform distributed double value in the interval ]0,1[
double rnd() {
return rk_double(&localState);
}
