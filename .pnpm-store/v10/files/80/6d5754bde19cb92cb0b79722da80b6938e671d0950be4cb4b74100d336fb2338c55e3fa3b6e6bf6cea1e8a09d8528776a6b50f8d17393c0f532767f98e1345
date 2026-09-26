"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.escapeHtml = escapeHtml;
exports.toUppercaseFirstLetter = toUppercaseFirstLetter;
exports.toLowercaseFirstLetter = toLowercaseFirstLetter;
exports.addPrefix = addPrefix;
exports.removePrefix = removePrefix;
var HTML_ESCAPE_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
};
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (character) { return HTML_ESCAPE_MAP[character]; });
}
function toUppercaseFirstLetter(string) {
    return string.toString().charAt(0).toUpperCase() + string.toString().slice(1);
}
function toLowercaseFirstLetter(string) {
    return string.toString().charAt(0).toLowerCase() + string.toString().slice(1);
}
function addPrefix(string, prefix) {
    return "".concat(prefix).concat(toUppercaseFirstLetter(string));
}
function removePrefix(string, prefix, lowercaseFirstLetter) {
    var _a;
    if (lowercaseFirstLetter === void 0) { lowercaseFirstLetter = true; }
    var inferPrefix = prefix || ((_a = string.match(/^([a-z][a-z0-9]+)/)) === null || _a === void 0 ? void 0 : _a[0]) || '';
    var withoutPrefix = string.replace(new RegExp("^(".concat(inferPrefix, ")")), '');
    return lowercaseFirstLetter ? toLowercaseFirstLetter(withoutPrefix) : withoutPrefix;
}
//# sourceMappingURL=string.js.map