// Identical author/state/name facts and attribute maps occur hundreds of
// times on dense lists. Intern them only within this reply. Nothing survives
// the capture, and geometry and text retain their original precision.
function packMetadata(rows) {
    const templates = [], templateIds = new Map(), attributes = [], attributeIds = new Map();
    function intern(value, table, ids) {
        const key = JSON.stringify(value);
        let id = ids.get(key);
        if (id === undefined) {
            id = table.length;
            table.push(value);
            ids.set(key, id);
        }
        return id;
    }
    function pack(row) {
        if (Array.isArray(row)) return row;
        if (row.author?.nodeType === 3 && !row.__nativeStatus) {
            return [-(1 + Number(!!row.author.visible) + 2 * Number(row.states.secure)), row.author.text || ''];
        }
        const {attributes:attrs, rect, __nativeFolded:folded, ...facts} = row;
        const record = [intern(facts, templates, templateIds)];
        if (attrs !== undefined) record[1] = intern(attrs, attributes, attributeIds);
        if (rect) record[2] = [rect.x, rect.y, rect.width, rect.height];
        if (folded) record[3] = folded.map(pack);
        return record;
    }
    const encoded = rows.map(pack);
    return JSON.stringify({templates, attributes, rows:encoded});
}
