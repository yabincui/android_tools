#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ElfW(what) Elf64_## what

bool ReadFully(FILE* fp, void* buf, size_t size, size_t offset) {
  int fd = fileno(fp);
  ssize_t rc = TEMP_FAILURE_RETRY(pread64(fd, buf, size, offset));
  if (rc < 0) {
    fprintf(stderr, "failed to read file: %s\n", strerror(errno));
    return false;
  }
  if (rc != size) {
    fprintf(stderr, "not read fully\n");
    return false;
  }
  return true;
}

bool readEhFrameHdr(FILE* fp, ElfW(Shdr)* section) {
  char data[section->sh_size];
  if (!ReadFully(fp, data, section->sh_size, section->sh_offset)) {
    return false;
  }
  printf("eh_frame_hdr: addr %lx offset %lx, size %lx\n",
         (unsigned long)section->sh_addr, (unsigned long)section->sh_offset,
         (unsigned long)section->sh_size);
  printf(" version: %d\n", data[0]);
  printf(" eh_frame_ptr_enc: %x\n", data[1]);
  printf(" fde_count_enc: %x\n", data[2]);
  printf(" table_enc: %x\n", data[3]);
  char eh_frame_ptr_enc = data[1];
  if ((eh_frame_ptr_enc & 0x0f) != 0x0b) {
    return false;
  }
  int32_t eh_frame_ptr = *(int32_t*)(&data[4]);
  printf("eh_frame_ptr = %x\n", eh_frame_ptr);
  char fde_count_enc = data[2];
  if ((fde_count_enc & 0x0f) != 0x03) {
    return false;
  }
  uint32_t fde_count = *(uint32_t*)(&data[8]);
  printf("fde_count = %u\n", fde_count);
  char table_enc = data[3];
  if (table_enc != 0x3b) {
    return false;
  }
  int32_t* p = (int32_t*)&data[12];
  for (int i = 0; i < fde_count; ++i) {
    int32_t loc = *p++;
    int32_t addr = *p++;
    printf("table[%d], loc %x, addr %x\n", i, loc, addr);
  }
  return true;
}

bool readEhFrame(FILE* fp, ElfW(Shdr)* section) {
  char data[section->sh_size];
  if (!ReadFully(fp, data, section->sh_size, section->sh_offset)) {
    return false;
  }
  printf("eh_frame: addr %lx offset %lx, size %lx\n",
         (unsigned long)section->sh_addr, (unsigned long)section->sh_offset,
         (unsigned long)section->sh_size);
  /*
  printf(" version: %d\n", data[0]);
  printf(" eh_frame_ptr_enc: %x\n", data[1]);
  printf(" fde_count_enc: %x\n", data[2]);
  printf(" table_enc: %x\n", data[3]);
  char eh_frame_ptr_enc = data[1];
  if ((eh_frame_ptr_enc & 0x0f) != 0x0b) {
    return false;
  }
  int32_t eh_frame_ptr = *(int32_t*)(&data[4]);
  printf("eh_frame_ptr = %x\n", eh_frame_ptr);
  char fde_count_enc = data[2];
  if ((fde_count_enc & 0x0f) != 0x03) {
    return false;
  }
  uint32_t fde_count = *(uint32_t*)(&data[8]);
  printf("fde_count = %u\n", fde_count);
  char table_enc = data[3];
  if (table_enc != 0x3b) {
    return false;
  }
  */
  return true;
}


bool readElf(const char* filename) {
  FILE* fp = fopen(filename, "rb");
  if (fp == nullptr) {
    fprintf(stderr, "failed to open %s\n", filename);
    return false;
  }
  ElfW(Ehdr) header;
  if (!ReadFully(fp, &header, sizeof(header), 0)) {
    return false;
  }
  if (memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) {
    fprintf(stderr, "elf magic doesn't match\n");
    return false;
  }
  int elf_class = header.e_ident[EI_CLASS];
  if (elf_class != ELFCLASS64) {
    fprintf(stderr, "elf format is 32-bit\n");
    return false;
  }
  // loop for each section
  printf("section offset: %lx\n", (unsigned long)header.e_shoff);
  printf("section num: %lx\n", (unsigned long)header.e_shnum);
  printf("section entry size: %lx\n", (unsigned long)header.e_shentsize);
  printf("string section index: %lu\n", (unsigned long)header.e_shstrndx);
  ElfW(Shdr) string_section;
  if (!ReadFully(fp, &string_section, sizeof(string_section), header.e_shoff + header.e_shstrndx * header.e_shentsize)) {
    return false;
  }
  char string_section_data[string_section.sh_size];
  if (!ReadFully(fp, string_section_data, string_section.sh_size, string_section.sh_offset)) {
    return false;
  }
  unsigned long offset;
  int i;
  for (i = 0, offset = header.e_shoff; i < header.e_shnum; ++i, offset += header.e_shentsize) {
    ElfW(Shdr) section;
    if (!ReadFully(fp, &section, sizeof(section), offset)) {
      return false;
    }
    const char* name = &string_section_data[section.sh_name];
    printf("section %d, offset %lx, name = %s(%lx)\n", i, offset, name, (unsigned long)section.sh_name);
    printf("  addr = %lx, offset = %lx, size = %lx\n", (unsigned long)section.sh_addr,
           (unsigned long)section.sh_offset, (unsigned long)section.sh_size);
  }
  // print eh_frame_hdr section
  for (i = 0, offset = header.e_shoff; i < header.e_shnum; ++i, offset += header.e_shentsize) {
    ElfW(Shdr) section;
    if (!ReadFully(fp, &section, sizeof(section), offset)) {
      return false;
    }
    const char* name = &string_section_data[section.sh_name];
    if (strcmp(name, ".eh_frame_hdr") == 0) {
      if (!readEhFrameHdr(fp, &section)) {
        fprintf(stderr, "read eh_frame_hdr failed\n");
        return false;
      }
    }
  }
  // print eh_frame section
  for (i = 0, offset = header.e_shoff; i < header.e_shnum; ++i, offset += header.e_shentsize) {
    ElfW(Shdr) section;
    if (!ReadFully(fp, &section, sizeof(section), offset)) {
      return false;
    }
    const char* name = &string_section_data[section.sh_name];
    if (strcmp(name, ".eh_frame") == 0) {
      if (!readEhFrame(fp, &section)) {
        fprintf(stderr, "read eh_frame failed\n");
        return false;
      }
    }
  }

  fclose(fp);
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "no filename\n");
    exit(1);
  }
  const char* filename = argv[1];
  readElf(filename);
}
