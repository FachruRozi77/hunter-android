CXX = clang++

CXXFLAGS = \
-O3 \
-std=c++17 \
-ffast-math \
-funroll-loops

LDFLAGS = \
-lcrypto \
-lpthread

OMP = -fopenmp

SRC = \
hunter-android.cpp \
Point.cpp \
Int.cpp \
IntGroup.cpp \
IntMod.cpp \
Random.cpp \
SECP256K1.cpp \
Timer.cpp

OBJ=$(SRC:.cpp=.o)

TARGET=hunter

all:
	$(CXX) $(CXXFLAGS) $(OMP) $(SRC) $(LDFLAGS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET)
