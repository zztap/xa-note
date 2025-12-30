import db from './db/index.js';
export function getSharedNote(code) {
    return db.prepare(`
    SELECT notes.*
    FROM shares
    JOIN notes ON notes.id = shares.note_id
    WHERE shares.id=?
  `).get(code);
}
//# sourceMappingURL=share.js.map