/* Rust <-> C++ bridge for Ghidra's Sleigh implementation. */
#pragma once

#include <memory>

#include "sleigh.hh"
#include "memstate.hh"
#include "slgh_compile.hh"

namespace ghidra {
class RustPCodeEmit;

class RustPCodeEmitProxy : public PcodeEmit
{
private:
    RustPCodeEmit *inner;

public:
    RustPCodeEmitProxy(RustPCodeEmit *emit) : inner(emit) {}

    virtual void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
                      VarnodeData *vars, int4 isize);
};

class RustLoadImage;

class RustLoadImageProxy : public LoadImage
{
private:
    RustLoadImage *inner;

public:
    RustLoadImageProxy(RustLoadImage *inner)
        : LoadImage("nofile"), inner(inner) {}

    virtual void loadFill(uint1 *ptr, int4 size, const Address &address);
    virtual std::string getArchType(void) const { return "plain"; }
    virtual void adjustVma(long adjust);
};

class RegisterData {
private:
    std::string name;
    VarnodeData varnode_data;

public:
    RegisterData(const std::string& name, const VarnodeData& varnode_data);
    const std::string& getName() const;
    const VarnodeData& getVarnodeData() const;
};

class UserOpData {
private:
    std::string name;
    uint4 index;

public:
    UserOpData(const std::string& name, uint4 index);
    const std::string& getName() const;
    uint4 getIndex() const;
};

// Load Image
std::unique_ptr<RustLoadImageProxy> newRustLoadImageProxy(RustLoadImage *loadImage);
void deleteRustLoadImageProxy(RustLoadImageProxy *ptr);

// DocumentStorage
std::unique_ptr<DocumentStorage> newDocumentStorage(const std::string &doc_contents);
void deleteDocumentStorage(DocumentStorage *ptr);

uint32_t getVarnodeSize(const VarnodeData &data);
AddrSpace *getVarnodeSpace(const VarnodeData &data);
uint64_t getVarnodeOffset(const VarnodeData &data);

// Sleigh
int32_t sleighOneInstruction(const Sleigh &sleigh, RustPCodeEmit *emit, uint64_t addr);
std::unique_ptr<std::vector<RegisterData>> getRegisters(const Sleigh &sleigh);
std::unique_ptr<std::vector<UserOpData>> getUserOps(const Sleigh &sleigh);

const VarnodeData &getRegisterProxy(const Sleigh &sleigh, const std::string &s);

std::unique_ptr<ContextInternal> new_context_internal();

std::unique_ptr<Address> new_address(AddrSpace *space, uintb offset);

std::unique_ptr<Sleigh> new_sleigh(LoadImage *ld, ContextDatabase *c_db);

std::unique_ptr<SleighCompile> new_sleigh_compile();
}

namespace rust
{
    namespace behavior
    {
        template <typename Try, typename Fail>
        static void trycatch(Try &&func, Fail &&fail) noexcept
        try
        {
            func();
        }
        catch (const ghidra::DecoderError &e)
        {
            fail("DecoderError");
        }
        catch (const ghidra::BadDataError &e)
        {
            fail("BadDataError");
        }
        catch (const ghidra::LowlevelError &e)
        {
            fail("Other error: " + e.explain);
        }
    }
}
