-- BTP Protocol Dissector for Wireshark
-- Dissects the custom BTP chunked protocol over BLE ATT

local btp_proto = Proto("btp_proto", "BTP Protocol Dissector")

-- Define fields for BTP Header

local f_message_id = ProtoField.uint16("btp.message_id", "Message ID", base.HEX, nil, 0, "Chunk message identifier")
local f_index = ProtoField.uint16("btp.index", "Index", base.DEC, nil, 0, "Current chunk index (0-based)")
local f_total_chunks = ProtoField.uint16("btp.total_chunks", "Total Chunks", base.DEC, nil, 0, "Total number of chunks in the message")
local f_data_len = ProtoField.uint8("btp.data_len", "Data Length", base.DEC, nil, 0, "Length of valid data in this chunk")
local f_padding = ProtoField.uint8("btp.padding", "Padding", base.HEX, nil, 0, "Unused padding byte")

-- Add fields to protocol
btp_proto.fields = {
    f_message_id,
    f_index,
    f_total_chunks,
    f_data_len,
    f_padding
}

-- Dissector function
function btp_proto.dissector(buffer, pinfo, tree)
    -- Find BTP header offset in the ATT value
    local btp_start = -1
    for i = 0, buffer:len() - 11 do
        local opcode = buffer(i, 1):uint()
        local handle = buffer(i+1, 2):le_uint()
        if (opcode == 0x52 and handle == 0x0010) or (opcode == 0x1b and handle == 0x0012) then
            btp_start = i + 3
            break
        end
    end

    if btp_start == -1 then
        return
    end

    local buf = buffer(btp_start)

    -- Set protocol column
    pinfo.cols.protocol = "BTP"

    -- Add BTP subtree
    local btp_tree = tree:add(btp_proto, buf(), "BTP Protocol Data")

    -- BTP Header (8 bytes, little-endian, starting at offset 0)
    local header_tree = btp_tree:add(buf(0, 8), "BTP Header")
    header_tree:add_le(f_message_id, buf(0, 2))
    header_tree:add_le(f_index, buf(2, 2))
    header_tree:add_le(f_total_chunks, buf(4, 2))
    header_tree:add(f_data_len, buf(6, 1))
    header_tree:add(f_padding, buf(7, 1))

    -- Chunk Data (from byte 8 onwards, length as per data_len)
    local data_len_val = buf(6, 1):uint()
    local data_start = 8
    local actual_data_len = math.min(data_len_val, buf:len() - data_start)

    if actual_data_len > 0 then
        local data_tree = btp_tree:add(buf(data_start, actual_data_len), "Chunk Data")
        data_tree:add(buf(data_start, actual_data_len), "Data (" .. actual_data_len .. " bytes): " .. buf(data_start, actual_data_len):bytes():tohex())
    end
end

-- Register as post-dissector for BLE ATT protocol
register_postdissector(btp_proto)
