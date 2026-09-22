local btp_proto = Proto("btp_proto", "BTP Protocol Dissector")
local l2cap_field = Field.new("btl2cap")

local f_sequence = ProtoField.uint16("btp.sequence", "Sequence", base.DEC)
local f_index = ProtoField.uint16("btp.index", "Index", base.DEC)
local f_record_len = ProtoField.uint24("btp.record_len", "Record Length", base.DEC)
local f_version = ProtoField.uint8("btp.version", "Version Tag", base.HEX)

local expert_invalid_version = ProtoExpert.new("btp.invalid_version", "BTP version tag is not 0xB2", expert.group.PROTOCOL, expert.severity.ERROR)
local expert_invalid_index = ProtoExpert.new("btp.invalid_index", "BTP chunk index is outside the record", expert.group.PROTOCOL, expert.severity.ERROR)
local expert_invalid_length = ProtoExpert.new("btp.invalid_length", "BTP record length is invalid", expert.group.PROTOCOL, expert.severity.ERROR)
local expert_short_chunk = ProtoExpert.new("btp.short_chunk", "BTP chunk data is truncated", expert.group.PROTOCOL, expert.severity.ERROR)

btp_proto.fields = {
    f_sequence,
    f_index,
    f_record_len,
    f_version
}
btp_proto.experts = {
    expert_invalid_version,
    expert_invalid_index,
    expert_invalid_length,
    expert_short_chunk
}

function btp_proto.dissector(buffer, pinfo, tree)
    local fi = l2cap_field()
    if fi then
        buffer = fi.tvb
    end

    local btp_start = -1
    for i = 0, buffer:len() - 11 do
        local opcode = buffer(i, 1):uint()
        local handle = buffer(i + 1, 2):le_uint()
        if (opcode == 0x52 and handle == 0x0010) or (opcode == 0x1b and handle == 0x0012) then
            btp_start = i + 3
            break
        end
    end

    if btp_start == -1 then
        return
    end

    local buf = buffer(btp_start)
    if buf:len() < 8 then
        return
    end

    pinfo.cols.protocol = "BTP"
    local btp_tree = tree:add(btp_proto, buf(), "BTP Protocol Data")
    local header_tree = btp_tree:add(buf(0, 8), "BTP Header")
    header_tree:add_le(f_sequence, buf(0, 2))
    header_tree:add_le(f_index, buf(2, 2))
    header_tree:add_le(f_record_len, buf(4, 3))
    header_tree:add(f_version, buf(7, 1))

    local index = buf(2, 2):le_uint()
    local record_len = buf(4, 3):le_uint()
    if buf(7, 1):uint() ~= 0xB2 then
        btp_tree:add_proto_expert_info(expert_invalid_version)
        return
    end
    if record_len == 0 or record_len > 128 * 1024 then
        btp_tree:add_proto_expert_info(expert_invalid_length)
        return
    end

    local chunk_data_size = 236
    local total_chunks = math.ceil(record_len / chunk_data_size)
    if index >= total_chunks then
        btp_tree:add_proto_expert_info(expert_invalid_index)
        return
    end

    local data_len = math.min(chunk_data_size, record_len - index * chunk_data_size)
    if buf:len() - 8 < data_len then
        btp_tree:add_proto_expert_info(expert_short_chunk)
        return
    end

    local data = buf(8, data_len)
    btp_tree:add(data, "Chunk Data (" .. data_len .. " bytes): " .. data:bytes():tohex())
end

register_postdissector(btp_proto)
