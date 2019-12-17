#include <cstdio>

#include <string>
#include <vector>
#include <utility>
#include <functional>

#include <Windows.h>

// コード領域を特定する
std::pair<unsigned int, unsigned int> getTextArea(HMODULE module) {
  const unsigned int baseAddr = reinterpret_cast<unsigned int>(module);
  const IMAGE_DOS_HEADER &mz = *reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddr);
  const IMAGE_NT_HEADERS32 &pe = *reinterpret_cast<const IMAGE_NT_HEADERS32 *>(baseAddr + mz.e_lfanew);
  const IMAGE_SECTION_HEADER * const sectionHeaders = reinterpret_cast<const IMAGE_SECTION_HEADER *>(pe.FileHeader.SizeOfOptionalHeader + reinterpret_cast<unsigned int>(&pe.OptionalHeader));
  const std::string target = ".text";
  for (unsigned int i = 0; i < pe.FileHeader.NumberOfSections; i++) {
    const IMAGE_SECTION_HEADER &section = sectionHeaders[i];
    if (target == reinterpret_cast<const char *>(section.Name)) {
      return std::make_pair(
        baseAddr + section.VirtualAddress,
        baseAddr + section.VirtualAddress + section.SizeOfRawData);
    }
  }
  return {};
}

// gadgetを探す
unsigned int searchGadget(const unsigned int size, std::function<bool(const unsigned char *)> func) {
  const std::pair<unsigned int, unsigned int> area = getTextArea(::GetModuleHandle("ntdll.dll"));
  for (unsigned int addr = area.first; addr < area.second - (size - 1); addr++) {
    if (func(reinterpret_cast<const unsigned char *>(addr))) {
      return addr;
    }
  }
  return 0;
}

// ROP内で使う数値出力関数
void __stdcall putsNumber(const unsigned int * const value) {
  std::printf("%d\n", *value);
}

// ROP内で使う文字出力関数
void __stdcall putsString(const char * const value) {
  std::printf("%s\n", value);
}

// ROP構築
std::vector<unsigned int> build(const unsigned int bufferAddress, const unsigned int stackBase, const unsigned int padding) {
  std::vector<unsigned int> rop;
  rop.resize(padding);

  // address群
  struct Data {
    unsigned int counter;
    char fizz[8];
    char buzz[8];
    char fizzbuzz[12];
  };
  Data &data = *reinterpret_cast<Data *>(bufferAddress);
  const unsigned int counter = reinterpret_cast<unsigned int>(&data.counter);
  const unsigned int fizz = reinterpret_cast<unsigned int>(&data.fizz);
  const unsigned int buzz = reinterpret_cast<unsigned int>(&data.buzz);
  const unsigned int fizzbuzz = reinterpret_cast<unsigned int>(&data.fizzbuzz);
  const unsigned int putsNumber = reinterpret_cast<unsigned int>(::putsNumber);
  const unsigned int putsString = reinterpret_cast<unsigned int>(::putsString);

  // gadget群
  const unsigned int ret = searchGadget(1, [](auto mem) {return mem[0] == 0xC3; });
  const unsigned int movEaxEcx = searchGadget(3, [](auto mem) {return mem[0] == 0x8B && mem[1] == 0xC1 && mem[2] == 0xC3; });
  const unsigned int popEcx = searchGadget(2, [](auto mem) {return mem[0] == 0x59 && mem[1] == 0xC3; });
  const unsigned int movDwordPtrDsEaxEcx = searchGadget(3, [](auto mem) {return mem[0] == 0x89 && mem[1] == 0x08 && mem[2] == 0xC3; });
  const unsigned int movEaxDwordPtrDsEax = searchGadget(3, [](auto mem) {return mem[0] == 0x8B && mem[1] == 0x00 && mem[2] == 0xC3; });
  const unsigned int incEax = searchGadget(2, [](auto mem) {return mem[0] == 0x40 && mem[1] == 0xC3; });
  const unsigned int xchgEaxEcx = searchGadget(2, [](auto mem) {return mem[0] == 0x91 && mem[1] == 0xC3; });
  const unsigned int xchgEaxEsp = searchGadget(2, [](auto mem) {return mem[0] == 0x94 && mem[1] == 0xC3; });

  // サブルーチン
  const auto incCounter = [&]() {
    rop.push_back(popEcx);
    rop.push_back(counter);
    rop.push_back(movEaxEcx);
    rop.push_back(movEaxDwordPtrDsEax);
    rop.push_back(incEax);
    rop.push_back(popEcx);
    rop.push_back(counter);
    rop.push_back(xchgEaxEcx);
    rop.push_back(movDwordPtrDsEaxEcx);
  };
  const auto callProc = [&](const unsigned int procAddress, const unsigned int stackSize) {
    // ローカル変数などでスタックが破壊されるので十分隙間を空けて関数を呼びだす
    const unsigned int loopStart = stackBase + (rop.size() * 4);
    const unsigned int count = 7 + 3 + stackSize - 1;
    rop.push_back(popEcx);
    rop.push_back(loopStart + count * 4);
    rop.push_back(movEaxEcx);
    rop.push_back(popEcx);
    rop.push_back(procAddress);
    rop.push_back(movDwordPtrDsEaxEcx);
    rop.push_back(popEcx);
    const unsigned int loopStart2 = stackBase + (rop.size() * 4);
    const unsigned int count2 = 3 + stackSize - 1;
    rop.push_back(loopStart2 + count2 * 4);
    rop.push_back(movEaxEcx);
    rop.push_back(xchgEaxEsp);
    rop.resize(rop.size() + stackSize);
  };
  const auto putCounter = [&]() {
    // putsNumber(data.counter);
    callProc(putsNumber, 1024);
    rop.push_back(ret);
    rop.push_back(counter);
  };
  const auto putFizz = [&]() {
    // puts(data.fizz);
    callProc(putsString, 1024);
    rop.push_back(ret);
    rop.push_back(fizz);
  };
  const auto putBuzz = [&]() {
    // puts(data.buzz);
    callProc(putsString, 1024);
    rop.push_back(ret);
    rop.push_back(buzz);
  };
  const auto putFizzBuzz = [&]() {
    // puts(data.fizzbuzz);
    callProc(putsString, 1024);
    rop.push_back(ret);
    rop.push_back(fizzbuzz);
  };

  const std::function<void()> round[] = {
    putCounter, putCounter, putFizz, putCounter, putBuzz,
    putFizz, putCounter, putCounter, putFizz, putBuzz,
    putCounter, putFizz, putCounter, putCounter, putFizzBuzz,
  };

  // data.fizz = "Fizz";
  rop.push_back(popEcx);
  rop.push_back(fizz);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0x7A7A6946);
  rop.push_back(movDwordPtrDsEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(fizz + 4);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0);
  rop.push_back(movDwordPtrDsEaxEcx);

  // data.fizz = "Buzz";
  rop.push_back(popEcx);
  rop.push_back(buzz);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0x7A7A7542);
  rop.push_back(movDwordPtrDsEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(buzz + 4);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0);
  rop.push_back(movDwordPtrDsEaxEcx);

  // data.fizzbuzz = "FizzBuzz";
  rop.push_back(popEcx);
  rop.push_back(fizzbuzz);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0x7A7A6946);
  rop.push_back(movDwordPtrDsEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(fizzbuzz + 4);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0x7A7A7542);
  rop.push_back(movDwordPtrDsEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(fizzbuzz + 8);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(0);
  rop.push_back(movDwordPtrDsEaxEcx);

  // data.counter = 1;
  rop.push_back(popEcx);
  rop.push_back(counter);
  rop.push_back(movEaxEcx);
  rop.push_back(popEcx);
  rop.push_back(1);
  rop.push_back(movDwordPtrDsEaxEcx);

  const unsigned int loopStart = stackBase + (rop.size() * 4);
  for (const auto put : round) {
    put();
    incCounter();
  }

  rop.push_back(popEcx);
  rop.push_back(loopStart);
  rop.push_back(movEaxEcx);
  rop.push_back(xchgEaxEsp); // ループ
  return rop;
}

// ROPをそのまま実行する
void run() {
  static const unsigned int ropSize = 65536;
  static char buffer[256];
  static unsigned int stackPtr;
  __asm {
    mov stackPtr, esp;
  };
  static unsigned int stackBase = stackPtr - ropSize;
  static std::vector<unsigned int> rop = build(reinterpret_cast<unsigned int>(buffer), stackBase, 0);
  if (rop.size() >= ropSize) {
    return;
  }
  rop.resize(ropSize);
  __asm {
    sub esp, ropSize;
  };
  std::memcpy(reinterpret_cast<unsigned char *>(stackBase), reinterpret_cast<unsigned char *>(&rop[0]), ropSize);
  __asm {
    ret;
  };
  // 帰ってこない
}

// ROP実行のBufferOverflow利用版
void run2Main() {
  static char buffer[256];
  char name[32];
  static std::vector<unsigned int> rop = build(reinterpret_cast<unsigned int>(buffer), reinterpret_cast<unsigned int>(&name), 12);
  ::memcpy(name, &rop[0], rop.size() * 4); // BufferOverflow!
  std::printf("name: %s\n", name);
  return;
}

// ROPするための領域確保用関数
void run2() {
  char dummy[65536 * 4];
  ::memset(dummy, 0, sizeof(dummy));
  run2Main();
  ::printf("%s", dummy);
  return;
}

// ただのFizzBuzz
void run3() {
  unsigned int i = 1;
  while (true) {
    putsNumber(&i); i++;
    putsNumber(&i); i++;
    putsString("Fizz"); i++;
    putsNumber(&i); i++;
    putsString("Buzz"); i++;
    putsString("Fizz"); i++;
    putsNumber(&i); i++;
    putsNumber(&i); i++;
    putsString("Fizz"); i++;
    putsString("Buzz"); i++;
    putsNumber(&i); i++;
    putsString("Fizz"); i++;
    putsNumber(&i); i++;
    putsNumber(&i); i++;
    putsString("FizzBuzz"); i++;
  }
}

int main() {
  run();
  return 0;
}
