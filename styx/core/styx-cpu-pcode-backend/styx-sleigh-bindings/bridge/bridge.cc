#include "bridge.hh"
// For cxx generated headers from our rust
#include "styx-sleigh-bindings/src/lib.rs.h"
#include <mutex>

namespace ghidra {

std::unique_ptr<DocumentStorage> newDocumentStorage(const std::string &doc_contents)
{
    // Creating/parsing xml docs is not thread safe so guard behind mutex.
    static std::mutex doc_lock;
    std::lock_guard<std::mutex> guard(doc_lock);

    // Create DocumentStorage on the heap
    auto doc = std::make_unique<DocumentStorage>();
    std::stringstream doc_stream;
    doc_stream << doc_contents;

    // this may throw a DecoderError
    auto root = doc->parseDocument(doc_stream)->getRoot();
    doc->registerTag(root);
    return doc;
}

std::unique_ptr<RustLoadImageProxy> newRustLoadImageProxy(RustLoadImage *loadImage)
{
    return std::make_unique<RustLoadImageProxy>(loadImage);
}

void RustLoadImageProxy::loadFill(uint1 *ptr, int4 size,
                                  const Address &address)
{
    return inner->load_fill(ptr, size, address);
}

void RustLoadImageProxy::adjustVma(long adjust)
{
    return inner->adjust_vma(adjust);
}

void deleteRustLoadImageProxy(RustLoadImageProxy *ptr)
{
    delete ptr;
}

void RustPCodeEmitProxy::dump(const Address &addr, OpCode opc,
                              VarnodeData *outvar, VarnodeData *vars,
                              int4 isize)
{
    std::vector<VarnodeData> vars_vec(vars, vars + isize);
    inner->dump(addr, (uint32_t)opc, outvar, vars_vec);
}

uint32_t getVarnodeSize(const VarnodeData &data) { return data.size; }
AddrSpace *getVarnodeSpace(const VarnodeData &data) { return data.space; }
uint64_t getVarnodeOffset(const VarnodeData &data) { return data.offset; }

// Sleigh
int32_t sleighOneInstruction(const Sleigh &sleigh, RustPCodeEmit *emit, uint64_t addr)
{
    auto address = Address(sleigh.getDefaultCodeSpace(), addr);
    auto pcode_emit = RustPCodeEmitProxy(emit);
    int32_t instruction_bytes = 0;

    instruction_bytes = sleigh.oneInstruction(pcode_emit, address);
    return instruction_bytes;
}

const VarnodeData &getRegisterProxy(const Sleigh &sleigh, const std::string &register_name)
{
    return sleigh.getRegister(register_name);
}

RegisterData::RegisterData(const std::string& name, const VarnodeData& varnode_data)
    : name(name), varnode_data(varnode_data) {}

const std::string& RegisterData::getName() const {
    return name;
}

const VarnodeData& RegisterData::getVarnodeData() const {
    return varnode_data;
}

std::unique_ptr<std::vector<RegisterData>> getRegisters(const Sleigh &sleigh)
{
    std::map<VarnodeData, std::string> register_list;
    sleigh.getAllRegisters(register_list);

    std::vector<RegisterData> reg_data_vec;
    std::map<VarnodeData, std::string>::iterator it;

    for (it = register_list.begin(); it != register_list.end(); it++)
    {
        RegisterData reg = RegisterData(it->second, it->first);
        reg_data_vec.push_back(reg);
    }

    return std::make_unique<std::vector<RegisterData>>(reg_data_vec);
}

UserOpData::UserOpData(const std::string& name, uint4 index)
    : name(name), index(index) {}

const std::string& UserOpData::getName() const {
    return name;
}

uint4 UserOpData::getIndex() const {
    return index;
}

std::unique_ptr<std::vector<UserOpData>> getUserOps(const Sleigh &sleigh)
{
    // Get list of user ops in sleigh object, then iterate over them to find
    // each user op index and format to UserOpData structure. Append these to a
    // new vector to return.
    std::vector<std::string> user_op_names;
    sleigh.getUserOpNames(user_op_names);

    std::vector<UserOpData> useropdata_list;
    for (std::string &userop_name : user_op_names) {
        UserOpSymbol *current_userop;
        current_userop = dynamic_cast<UserOpSymbol *>(sleigh.findSymbol(userop_name));

        useropdata_list.push_back(UserOpData(userop_name, current_userop->getIndex()));
    }

    return std::make_unique<std::vector<UserOpData>>(useropdata_list);
}


std::unique_ptr<ContextInternal> new_context_internal() {
    return std::unique_ptr<ContextInternal>(new ContextInternal());
}

std::unique_ptr<Address> new_address(AddrSpace *space, uintb offset) {
    return std::unique_ptr<Address>(new Address(space, offset));
}

std::unique_ptr<Sleigh> new_sleigh(LoadImage *ld, ContextDatabase *c_db) {
    return std::unique_ptr<Sleigh>(new Sleigh(ld, c_db));
}

std::unique_ptr<SleighCompile> new_sleigh_compile() {
    return std::unique_ptr<SleighCompile>(new SleighCompile());
}
}
