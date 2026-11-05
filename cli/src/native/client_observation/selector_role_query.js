// Raw `role=` engine ported from Playwright 1.64.1
// `packages/injected/src/roleSelectorEngine.ts`, `roleUtils.ts`, and the
// attribute-selector body parser in `selectorUtils.ts`. See
// selector-NOTICE.md for provenance, hashes and the bounded subset.
//
// The body is the same typed attribute selector Playwright parses after the
// role name (`button[name="Save"][disabled]`), so the authored text is data.
// Matching computes the ARIA role and accessible name from the authored DOM
// exactly like the pinned engine: the query descends into open shadow roots,
// never matches its own root, and refuses malformed bodies as invalid locators.
//
// Security: accessible-name acquisition reuses the existing issued inventory
// realm, but never reads text or editable values under a secure/protected
// node. That is a deliberate native boundary, recorded in selector-NOTICE.md.

const roleValidRoles = [
  "alert", "alertdialog", "application", "article", "banner", "blockquote", "button", "caption", "cell", "checkbox",
  "code", "columnheader", "combobox", "complementary", "contentinfo", "definition", "deletion", "dialog", "directory",
  "document", "emphasis", "feed", "figure", "form", "generic", "grid", "gridcell", "group", "heading", "img", "insertion",
  "link", "list", "listbox", "listitem", "log", "main", "mark", "marquee", "math", "meter", "menu", "menubar", "menuitem",
  "menuitemcheckbox", "menuitemradio", "navigation", "none", "note", "option", "paragraph", "presentation", "progressbar",
  "radio", "radiogroup", "region", "row", "rowgroup", "rowheader", "scrollbar", "search", "searchbox", "separator",
  "slider", "spinbutton", "status", "strong", "subscript", "superscript", "switch", "tab", "table", "tablist", "tabpanel",
  "term", "textbox", "time", "timer", "toolbar", "tooltip", "tree", "treegrid", "treeitem",
];
const roleSupportedAttributes = ["selected", "checked", "pressed", "expanded", "level", "disabled", "name", "description", "include-hidden"].sort();
const roleAriaSelectedRoles = ["gridcell", "option", "row", "tab", "rowheader", "columnheader", "treeitem"];
const roleAriaCheckedRoles = ["checkbox", "menuitemcheckbox", "option", "radio", "switch", "menuitemradio", "treeitem"];
const roleAriaPressedRoles = ["button"];
const roleAriaExpandedRoles = ["application", "button", "checkbox", "combobox", "gridcell", "link", "listbox", "menuitem", "row", "rowheader", "tab", "treeitem", "columnheader", "menuitemcheckbox", "menuitemradio", "rowheader", "switch"];
const roleAriaLevelRoles = ["heading", "listitem", "row", "treeitem"];
const roleAriaDisabledRoles = ["application", "button", "composite", "gridcell", "group", "input", "link", "menuitem", "scrollbar", "separator", "tab", "checkbox", "columnheader", "combobox", "grid", "listbox", "menu", "menubar", "menuitemcheckbox", "menuitemradio", "option", "radio", "radiogroup", "row", "rowheader", "searchbox", "select", "slider", "spinbutton", "switch", "tablist", "textbox", "toolbar", "tree", "treegrid", "treeitem"];
const roleInputTypeToRole = {
  "button": "button", "checkbox": "checkbox", "image": "button", "number": "spinbutton",
  "radio": "radio", "range": "slider", "reset": "button", "submit": "button",
};
const roleImplicitByTagName = {
  "A": (e) => e.hasAttribute("href") ? "link" : null,
  "AREA": (e) => e.hasAttribute("href") ? "link" : null,
  "ARTICLE": () => "article",
  "ASIDE": () => "complementary",
  "BLOCKQUOTE": () => "blockquote",
  "BUTTON": () => "button",
  "CAPTION": () => "caption",
  "CODE": () => "code",
  "DATALIST": () => "listbox",
  "DD": () => "definition",
  "DEL": () => "deletion",
  "DETAILS": () => "group",
  "DFN": () => "term",
  "DIALOG": () => "dialog",
  "DT": () => "term",
  "EM": () => "emphasis",
  "FIELDSET": () => "group",
  "FIGURE": () => "figure",
  "FOOTER": (e) => roleClosestCrossShadow(e, roleAncestorPreventingLandmark) ? null : "contentinfo",
  "FORM": (e) => roleHasExplicitAccessibleName(e) ? "form" : null,
  "H1": () => "heading",
  "H2": () => "heading",
  "H3": () => "heading",
  "H4": () => "heading",
  "H5": () => "heading",
  "H6": () => "heading",
  "HEADER": (e) => roleClosestCrossShadow(e, roleAncestorPreventingLandmark) ? null : "banner",
  "HR": () => "separator",
  "HTML": () => "document",
  "IMG": (e) => e.getAttribute("alt") === "" && !e.getAttribute("title") && !roleHasGlobalAriaAttribute(e) && !roleHasTabIndex(e) ? "presentation" : "img",
  "INPUT": (e) => {
    const type = e.type.toLowerCase();
    if (["email", "search", "tel", "text", "url", ""].includes(type)) {
      const list = roleGetIdRefs(e, e.getAttribute("list"))[0];
      if (list && roleElementSafeTagName(list) === "DATALIST") return "combobox";
      return type === "search" ? "searchbox" : "textbox";
    }
    if (type === "hidden") return null;
    if (type === "file") return "button";
    return roleInputTypeToRole[type] || "textbox";
  },
  "INS": () => "insertion",
  "LI": () => "listitem",
  "MAIN": () => "main",
  "MARK": () => "mark",
  "MATH": () => "math",
  "MENU": () => "list",
  "METER": () => "meter",
  "NAV": () => "navigation",
  "OL": () => "list",
  "OPTGROUP": () => "group",
  "OPTION": () => "option",
  "OUTPUT": () => "status",
  "P": () => "paragraph",
  "PROGRESS": () => "progressbar",
  "SEARCH": () => "search",
  "SECTION": (e) => roleHasExplicitAccessibleName(e) ? "region" : null,
  "SELECT": (e) => roleIsListBoxSelect(e) ? "listbox" : "combobox",
  "STRONG": () => "strong",
  "SUB": () => "subscript",
  "SUP": () => "superscript",
  "SVG": () => "img",
  "TABLE": () => "table",
  "TBODY": () => "rowgroup",
  "TD": (e) => {
    const table = roleClosestCrossShadow(e, "table");
    const tableRole = table ? roleGetExplicitAriaRole(table) : "";
    return tableRole === "grid" || tableRole === "treegrid" ? "gridcell" : "cell";
  },
  "TEXTAREA": () => "textbox",
  "TFOOT": () => "rowgroup",
  "TH": (e) => {
    const scope = e.getAttribute("scope");
    if (scope === "col" || scope === "colgroup") return "columnheader";
    if (scope === "row" || scope === "rowgroup") return "rowheader";
    const nextSibling = e.nextElementSibling;
    const prevSibling = e.previousElementSibling;
    const row = !!e.parentElement && roleElementSafeTagName(e.parentElement) === "TR" ? e.parentElement : undefined;
    if (!nextSibling && !prevSibling) {
      if (row) {
        const table = roleClosestCrossShadow(row, "table");
        if (table && table.rows.length <= 1) return null;
      }
      return "columnheader";
    }
    if (roleIsHeaderCell(nextSibling) && roleIsHeaderCell(prevSibling)) return "columnheader";
    if (roleIsNonEmptyDataCell(nextSibling) || roleIsNonEmptyDataCell(prevSibling)) return "rowheader";
    return "columnheader";
  },
  "THEAD": () => "rowgroup",
  "TIME": () => "time",
  "TR": () => "row",
  "UL": () => "list",
};
const roleAncestorPreventingLandmark = "article:not([role]), aside:not([role]), main:not([role]), nav:not([role]), section:not([role]), [role=article], [role=complementary], [role=main], [role=navigation], [role=region]";
const roleGlobalAriaAttributes = [
  ["aria-atomic"], ["aria-busy"], ["aria-controls"], ["aria-current"], ["aria-describedby"], ["aria-details"],
  ["aria-dropeffect"], ["aria-flowto"],
  ["aria-grabbed"],
  ["aria-haspopup"],
  ["aria-hidden"],
  ["aria-invalid"],
  ["aria-keyshortcuts"],
  ["aria-label", ["caption", "code", "deletion", "emphasis", "generic", "insertion", "paragraph", "presentation", "strong", "subscript", "superscript"]],
  ["aria-labelledby", ["caption", "code", "deletion", "emphasis", "generic", "insertion", "paragraph", "presentation", "strong", "subscript", "superscript"]],
  ["aria-live"], ["aria-owns"], ["aria-relevant"],
  ["aria-roledescription", ["generic"]],
];
const rolePresentationInheritanceParents = {
  "DD": ["DL", "DIV"],
  "DIV": ["DL"],
  "DT": ["DL", "DIV"],
  "LI": ["OL", "UL"],
  "TBODY": ["TABLE"],
  "TD": ["TR"],
  "TFOOT": ["TABLE"],
  "TH": ["TR"],
  "THEAD": ["TABLE"],
  "TR": ["THEAD", "TBODY", "TFOOT", "TABLE"],
};

let roleRoleCache = null;
let roleHiddenCache = null;
let roleAccessibleNameCache = null;
let roleAccessibleNameHiddenCache = null;
let roleAccessibleDescriptionCache = null;
let roleAccessibleDescriptionHiddenCache = null;
let roleStyleCache = null;
let roleStyleBeforeCache = null;
let roleStyleAfterCache = null;
let roleVisibilityCache = null;
let rolePseudoContentCache = null;
let rolePseudoBeforeCache = null;
let rolePseudoAfterCache = null;
let roleAriaDisabledCache = null;

function roleBeginCaches() {
  matcherStep();
  roleRoleCache = roleRoleCache || new Map();
  roleHiddenCache = roleHiddenCache || new Map();
  roleAccessibleNameCache = roleAccessibleNameCache || new Map();
  roleAccessibleNameHiddenCache = roleAccessibleNameHiddenCache || new Map();
  roleAccessibleDescriptionCache = roleAccessibleDescriptionCache || new Map();
  roleAccessibleDescriptionHiddenCache = roleAccessibleDescriptionHiddenCache || new Map();
  roleStyleCache = roleStyleCache || new Map();
  roleStyleBeforeCache = roleStyleBeforeCache || new Map();
  roleStyleAfterCache = roleStyleAfterCache || new Map();
  roleVisibilityCache = roleVisibilityCache || new Map();
  rolePseudoContentCache = rolePseudoContentCache || new Map();
  rolePseudoBeforeCache = rolePseudoBeforeCache || new Map();
  rolePseudoAfterCache = rolePseudoAfterCache || new Map();
  roleAriaDisabledCache = roleAriaDisabledCache || new Map();
}

function roleEndCaches() {
  roleRoleCache = null;
  roleHiddenCache = null;
  roleAccessibleNameCache = null;
  roleAccessibleNameHiddenCache = null;
  roleAccessibleDescriptionCache = null;
  roleAccessibleDescriptionHiddenCache = null;
  roleStyleCache = null;
  roleStyleBeforeCache = null;
  roleStyleAfterCache = null;
  roleVisibilityCache = null;
  rolePseudoContentCache = null;
  rolePseudoBeforeCache = null;
  rolePseudoAfterCache = null;
  roleAriaDisabledCache = null;
}

function roleElementSafeTagName(element) {
  const tagName = element.tagName;
  if (typeof tagName === "string") {
    const first = tagName.charCodeAt(0);
    if (first >= 97 && first <= 122) return tagName.toUpperCase();
    return tagName;
  }
  return element instanceof HTMLFormElement ? "FORM" : element.tagName.toUpperCase();
}

function roleParentElementOrShadowHost(element) {
  if (element.parentElement) return element.parentElement;
  if (!element.parentNode) return;
  if (element.parentNode.nodeType === 11 && element.parentNode.host) return element.parentNode.host;
}

function roleEnclosingShadowRootOrDocument(element) {
  let node = element;
  while (node.parentNode) node = node.parentNode;
  if (node.nodeType === 11 || node.nodeType === 9) return node;
}

function roleEnclosingShadowHost(element) {
  while (element.parentElement) element = element.parentElement;
  return roleParentElementOrShadowHost(element);
}

function roleClosestCrossShadow(element, css, scope) {
  while (element) {
    matcherStep();
    const closest = element.closest(css);
    if (scope && closest !== scope && closest && closest.contains(scope)) return;
    if (closest) return closest;
    element = roleEnclosingShadowHost(element);
  }
}

function roleGetStyle(element, pseudo) {
  const cache = pseudo === "::before" ? roleStyleBeforeCache : pseudo === "::after" ? roleStyleAfterCache : roleStyleCache;
  if (!cache) return element.ownerDocument && element.ownerDocument.defaultView ? element.ownerDocument.defaultView.getComputedStyle(element, pseudo) : undefined;
  if (cache.has(element)) return cache.get(element);
  const style = element.ownerDocument && element.ownerDocument.defaultView ? element.ownerDocument.defaultView.getComputedStyle(element, pseudo) : undefined;
  cache.set(element, style);
  return style;
}

function roleStyleVisibilityVisible(element, style) {
  const cached = roleVisibilityCache ? roleVisibilityCache.get(element) : undefined;
  if (cached !== undefined) return cached;
  const actual = style !== undefined ? style : roleGetStyle(element);
  let result = true;
  if (actual) {
    if (!element.checkVisibility()) result = false;
    else if (actual.visibility !== "visible") result = false;
  }
  if (roleVisibilityCache) roleVisibilityCache.set(element, result);
  return result;
}

function roleIsListBoxSelect(select) {
  return select.multiple || select.size > 1;
}

function roleVisibleTextNode(node) {
  const document = node.ownerDocument;
  if (!document) return false;
  const range = document.createRange();
  range.selectNode(node);
  const rect = range.getBoundingClientRect();
  matcherStep();
  return rect.width > 0 && rect.height > 0;
}

function roleIsIgnoredForAria(element) {
  return ["STYLE", "SCRIPT", "NOSCRIPT", "TEMPLATE"].includes(roleElementSafeTagName(element));
}

function roleAriaBoolean(attr) {
  return attr === null ? undefined : attr.toLowerCase() === "true";
}

function roleBelongsToHidden(element, depth) {
  matcherStep();
  if (depth > 256) throw matcherLimit;
  let hidden = roleHiddenCache ? roleHiddenCache.get(element) : undefined;
  if (hidden === undefined) {
    hidden = false;
    if (element.parentElement && element.parentElement.shadowRoot && !element.assignedSlot) hidden = true;
    if (!hidden) {
      const style = roleGetStyle(element);
      hidden = !style || style.display === "none" || roleAriaBoolean(element.getAttribute("aria-hidden")) === true;
    }
    if (!hidden) {
      const parent = roleParentElementOrShadowHost(element);
      if (parent) hidden = roleBelongsToHidden(parent, depth + 1);
    }
    if (roleHiddenCache) roleHiddenCache.set(element, hidden);
  }
  return hidden;
}

function roleElementHiddenForAria(element, depth = 0) {
  matcherStep();
  if (depth > 256) throw matcherLimit;
  if (roleIsIgnoredForAria(element)) return true;
  const style = roleGetStyle(element);
  const isSlot = element.nodeName === "SLOT";
  if (style && style.display === "contents" && !isSlot) {
    for (let child = element.firstChild; child; child = child.nextSibling) {
      matcherStep();
      if (child.nodeType === 1 && !roleElementHiddenForAria(child, depth + 1)) return false;
      if (child.nodeType === 3 && roleVisibleTextNode(child)) return false;
    }
    return true;
  }
  const isOptionInsideSelect = element.nodeName === "OPTION" && !!element.closest("select");
  if (!isOptionInsideSelect && !isSlot && !roleStyleVisibilityVisible(element, style)) return true;
  return roleBelongsToHidden(element, depth);
}

function roleHasGlobalAriaAttribute(element, forRole) {
  return roleGlobalAriaAttributes.some(([attr, prohibited]) => {
    return !(prohibited && prohibited.includes(forRole || "")) && element.hasAttribute(attr);
  });
}

function roleHasTabIndex(element) {
  return !Number.isNaN(Number(String(element.getAttribute("tabindex"))));
}

function roleIsNativelyFocusable(element) {
  const tagName = roleElementSafeTagName(element);
  if (["BUTTON", "DETAILS", "SELECT", "TEXTAREA"].includes(tagName)) return true;
  if (tagName === "A" || tagName === "AREA") return element.hasAttribute("href");
  if (tagName === "INPUT") return !element.hidden;
  return false;
}

function roleIsFocusable(element) {
  return !roleIsNativelyDisabled(element) && (roleIsNativelyFocusable(element) || roleHasTabIndex(element));
}

function roleIsHeaderCell(element) {
  return !!element && roleElementSafeTagName(element) === "TH";
}

function roleIsNonEmptyDataCell(element) {
  if (!element || roleElementSafeTagName(element) !== "TD") return false;
  return !!((element.textContent && element.textContent.trim()) || element.children.length > 0);
}

function roleHasExplicitAccessibleName(element) {
  return element.hasAttribute("aria-label") || element.hasAttribute("aria-labelledby");
}

function roleGetExplicitAriaRole(element) {
  const roles = (element.getAttribute("role") || "").split(" ").map((role) => role.trim());
  return roles.find((role) => roleValidRoles.includes(role)) || null;
}

function roleHasPresentationConflictResolution(element, role) {
  return roleHasGlobalAriaAttribute(element, role) || roleIsFocusable(element);
}

function roleGetImplicitAriaRole(element) {
  const implicitRole = (roleImplicitByTagName[roleElementSafeTagName(element)] || (() => null)).call(roleImplicitByTagName, element) || "";
  if (!implicitRole) return null;
  let ancestor = element;
  while (ancestor) {
    matcherStep();
    const parent = roleParentElementOrShadowHost(ancestor);
    const parents = rolePresentationInheritanceParents[roleElementSafeTagName(ancestor)];
    if (!parents || !parent || !parents.includes(roleElementSafeTagName(parent))) break;
    const parentExplicitRole = roleGetExplicitAriaRole(parent);
    if ((parentExplicitRole === "none" || parentExplicitRole === "presentation") && !roleHasPresentationConflictResolution(parent, parentExplicitRole)) return parentExplicitRole;
    ancestor = parent;
  }
  return implicitRole;
}

function roleGetAriaRole(element) {
  const cached = roleRoleCache ? roleRoleCache.get(element) : undefined;
  if (cached !== undefined) return cached;
  const explicitRole = roleGetExplicitAriaRole(element);
  let role;
  if (!explicitRole) {
    role = roleGetImplicitAriaRole(element);
  } else if (explicitRole === "none" || explicitRole === "presentation") {
    const implicitRole = roleGetImplicitAriaRole(element);
    role = roleHasPresentationConflictResolution(element, implicitRole) ? implicitRole : explicitRole;
  } else {
    role = explicitRole;
  }
  if (roleRoleCache) roleRoleCache.set(element, role);
  return role;
}

function roleIsNativelyDisabled(element) {
  const isNativeFormControl = ["BUTTON", "INPUT", "SELECT", "TEXTAREA", "OPTION", "OPTGROUP"].includes(roleElementSafeTagName(element));
  return isNativeFormControl && (element.hasAttribute("disabled") || roleBelongsToDisabledOptGroup(element) || roleBelongsToDisabledFieldSet(element));
}

function roleBelongsToDisabledOptGroup(element) {
  return roleElementSafeTagName(element) === "OPTION" && !!element.closest("OPTGROUP[DISABLED]");
}

function roleBelongsToDisabledFieldSet(element) {
  const fieldSetElement = element && element.closest("FIELDSET[DISABLED]");
  if (!fieldSetElement) return false;
  const legendElement = fieldSetElement.querySelector(":scope > LEGEND");
  return !legendElement || !legendElement.contains(element);
}

function roleHasAriaDisabledInChain(element) {
  let result = roleAriaDisabledCache ? roleAriaDisabledCache.get(element) : undefined;
  if (result === undefined) {
    const attribute = (element.getAttribute("aria-disabled") || "").toLowerCase();
    if (attribute === "true") {
      result = true;
    } else if (attribute === "false") {
      result = false;
    } else {
      const parent = roleParentElementOrShadowHost(element);
      result = parent ? roleHasAriaDisabledInChain(parent) : false;
    }
    if (roleAriaDisabledCache) roleAriaDisabledCache.set(element, result);
  }
  return result;
}

function roleHasExplicitAriaDisabled(element) {
  if (!roleAriaDisabledRoles.includes(roleGetAriaRole(element) || "")) return false;
  return roleHasAriaDisabledInChain(element);
}

function roleGetAriaDisabled(element) {
  return roleIsNativelyDisabled(element) || roleHasExplicitAriaDisabled(element);
}

function roleGetAriaSelected(element) {
  if (roleElementSafeTagName(element) === "OPTION") return element.selected;
  if (roleAriaSelectedRoles.includes(roleGetAriaRole(element) || "")) return roleAriaBoolean(element.getAttribute("aria-selected")) === true;
  return false;
}

function roleGetChecked(element, allowMixed) {
  const tagName = roleElementSafeTagName(element);
  if (allowMixed && tagName === "INPUT" && element.indeterminate) return "mixed";
  if (tagName === "INPUT" && ["checkbox", "radio"].includes(element.type)) return element.checked;
  if (roleAriaCheckedRoles.includes(roleGetAriaRole(element) || "")) {
    const checked = element.getAttribute("aria-checked");
    if (checked === "true") return true;
    if (allowMixed && checked === "mixed") return "mixed";
    return false;
  }
  return "error";
}

function roleGetAriaChecked(element) {
  const result = roleGetChecked(element, true);
  return result === "error" ? false : result;
}

function roleGetAriaPressed(element) {
  if (roleAriaPressedRoles.includes(roleGetAriaRole(element) || "")) {
    const pressed = element.getAttribute("aria-pressed");
    if (pressed === "true") return true;
    if (pressed === "mixed") return "mixed";
  }
  return false;
}

function roleGetAriaExpanded(element) {
  if (roleElementSafeTagName(element) === "DETAILS") return element.open;
  if (roleAriaExpandedRoles.includes(roleGetAriaRole(element) || "")) {
    const expanded = element.getAttribute("aria-expanded");
    if (expanded === null) return undefined;
    if (expanded === "true") return true;
    return false;
  }
  return undefined;
}

function roleGetAriaLevel(element) {
  const native = { "H1": 1, "H2": 2, "H3": 3, "H4": 4, "H5": 5, "H6": 6 }[roleElementSafeTagName(element)];
  if (native) return native;
  if (roleAriaLevelRoles.includes(roleGetAriaRole(element) || "")) {
    const attr = element.getAttribute("aria-level");
    const value = attr === null ? Number.NaN : Number(attr);
    if (Number.isInteger(value) && value >= 1) return value;
  }
  return 0;
}

function roleGetIdRefs(element, ref) {
  if (!ref) return [];
  const root = roleEnclosingShadowRootOrDocument(element);
  if (!root) return [];
  try {
    const ids = ref.split(" ").filter((id) => !!id);
    const result = [];
    for (const id of ids) {
      matcherStep();
      const firstElement = root.querySelector("#" + CSS.escape(id));
      if (firstElement && !result.includes(firstElement)) result.push(firstElement);
    }
    return result;
  } catch (error) {
    if (error === matcherLimit) throw error;
    return [];
  }
}

function roleGetAriaLabelledByElements(element) {
  const ref = element.getAttribute("aria-labelledby");
  if (ref === null) return null;
  const refs = roleGetIdRefs(element, ref);
  return refs.length ? refs : null;
}

function roleQueryInAriaOwned(element, selector) {
  const result = [...element.querySelectorAll(selector)];
  for (const owned of roleGetIdRefs(element, element.getAttribute("aria-owns"))) {
    matcherStep();
    if (owned.matches(selector)) result.push(owned);
    result.push(...owned.querySelectorAll(selector));
  }
  return result;
}

function roleAllowsNameFromContent(role, targetDescendant) {
  const alwaysAllowsNameFromContent = ["button", "cell", "checkbox", "columnheader", "gridcell", "heading", "link", "menuitem", "menuitemcheckbox", "menuitemradio", "option", "radio", "row", "rowheader", "switch", "tab", "tooltip", "treeitem"].includes(role);
  const descendantAllowsNameFromContent = targetDescendant && ["", "caption", "code", "contentinfo", "definition", "deletion", "emphasis", "insertion", "list", "listitem", "mark", "none", "paragraph", "presentation", "region", "row", "rowgroup", "section", "strong", "subscript", "superscript", "table", "term", "time"].includes(role);
  return alwaysAllowsNameFromContent || descendantAllowsNameFromContent;
}

function roleNormalizeWhiteSpace(text) {
  return text.replace(/[\u200b\u00ad]/g, "").trim().replace(/\s+/g, " ");
}

function roleAsFlatString(s) {
  return s.split("\xA0").map((chunk) => chunk.replace(/\r\n/g, "\n").replace(/[\u200b\u00ad]/g, "").replace(/\s\s*/g, " ")).join("\xA0").trim();
}

function roleTextBlocked(node) {
  const seen = new Set();
  let depth = 0;
  for (let current = node; current; current = current.parentElement || (current.getRootNode && current.getRootNode().host)) {
    matcherStep();
    if (++depth > 256 || seen.has(current)) throw matcherLimit;
    seen.add(current);
    if (current.nodeType === 1 && (protectedNodes.has(current) || secureNode(current))) return true;
  }
  return false;
}

function roleProtectedValue(element) {
  return roleTextBlocked(element) ? "" : element.value;
}

function roleInnerAccumulatedText(element, options) {
  const tokens = [];
  const visit = (node, skipSlotted) => {
    matcherStep();
    if (skipSlotted && node.assignedSlot) return;
    if (node.nodeType === 1) {
      const style = roleGetStyle(node);
      const display = (style && style.display) || "inline";
      let token = roleTextAlternative(node, options);
      if (display !== "inline" || node.nodeName === "BR") token = " " + token + " ";
      tokens.push(token);
    } else if (node.nodeType === 3) {
      if (!roleTextBlocked(node)) tokens.push(node.textContent || "");
    }
  };
  tokens.push(roleGetCSSContent(element, "::before") || "");
  const content = roleGetCSSContent(element);
  if (content !== undefined) {
    tokens.push(content);
  } else {
    const assignedNodes = element.nodeName === "SLOT" ? element.assignedNodes() : [];
    if (assignedNodes.length) {
      for (const child of assignedNodes) visit(child, false);
    } else {
      for (let child = element.firstChild; child; child = child.nextSibling) visit(child, true);
      if (element.shadowRoot) {
        for (let child = element.shadowRoot.firstChild; child; child = child.nextSibling) visit(child, true);
      }
      for (const owned of roleGetIdRefs(element, element.getAttribute("aria-owns"))) visit(owned, true);
    }
  }
  tokens.push(roleGetCSSContent(element, "::after") || "");
  return tokens.join("");
}

function roleTextAlternative(element, options) {
  matcherStep();
  if (options.visited.has(element)) return "";
  const childOptions = {
    ...options,
    embeddedInTargetElement: options.embeddedInTargetElement === "self" ? "descendant" : options.embeddedInTargetElement,
  };
  if (!options.includeHidden) {
    const hiddenReferenceTraversal = !!((options.embeddedInLabelledBy || {}).hidden || (options.embeddedInDescribedBy || {}).hidden || (options.embeddedInNativeTextAlternative || {}).hidden || (options.embeddedInLabel || {}).hidden);
    if (roleIsIgnoredForAria(element) || (!hiddenReferenceTraversal && roleElementHiddenForAria(element))) {
      options.visited.add(element);
      return "";
    }
  }
  if (roleTextBlocked(element)) {
    options.visited.add(element);
    return "";
  }
  const labelledBy = roleGetAriaLabelledByElements(element);
  if (!options.embeddedInLabelledBy) {
    const accessibleName = (labelledBy || []).map((ref) => roleTextAlternative(ref, {
      ...options,
      embeddedInLabelledBy: { element: ref, hidden: roleElementHiddenForAria(ref) },
      embeddedInDescribedBy: undefined,
      embeddedInTargetElement: undefined,
      embeddedInLabel: undefined,
      embeddedInNativeTextAlternative: undefined,
    })).join(" ");
    if (accessibleName) return accessibleName;
  }
  const role = roleGetAriaRole(element) || "";
  const tagName = roleElementSafeTagName(element);
  if (!!options.embeddedInLabel || !!options.embeddedInLabelledBy || options.embeddedInTargetElement === "descendant") {
    const isOwnLabel = [...(element.labels || [])].includes(element);
    const isOwnLabelledBy = (labelledBy || []).includes(element);
    if (!isOwnLabel && !isOwnLabelledBy) {
      if (role === "textbox" || role === "searchbox") {
        options.visited.add(element);
        if (tagName === "INPUT" || tagName === "TEXTAREA") return roleProtectedValue(element);
        return element.textContent;
      }
      if (["combobox", "listbox"].includes(role)) {
        options.visited.add(element);
        let selectedOptions;
        if (tagName === "SELECT") {
          selectedOptions = [...element.selectedOptions];
          if (!selectedOptions.length && element.options.length) selectedOptions.push(element.options[0]);
        } else {
          const listbox = role === "combobox" ? roleQueryInAriaOwned(element, "*").find((candidate) => roleGetAriaRole(candidate) === "listbox") : element;
          selectedOptions = listbox ? roleQueryInAriaOwned(listbox, '[aria-selected="true"]').filter((candidate) => roleGetAriaRole(candidate) === "option") : [];
        }
        if (!selectedOptions.length && tagName === "INPUT") return roleProtectedValue(element);
        return selectedOptions.map((option) => roleTextAlternative(option, childOptions)).join(" ");
      }
      if (["progressbar", "scrollbar", "slider", "spinbutton", "meter"].includes(role)) {
        options.visited.add(element);
        if (element.hasAttribute("aria-valuetext")) return element.getAttribute("aria-valuetext") || "";
        if (element.hasAttribute("aria-valuenow")) return element.getAttribute("aria-valuenow") || "";
        return element.getAttribute("value") || "";
      }
      if (role === "menu") {
        options.visited.add(element);
        return "";
      }
    }
  }
  const ariaLabel = element.getAttribute("aria-label") || "";
  if (ariaLabel.trim()) {
    options.visited.add(element);
    return ariaLabel;
  }
  if (!["presentation", "none"].includes(role)) {
    if (tagName === "INPUT" && ["button", "submit", "reset"].includes(element.type)) {
      options.visited.add(element);
      const value = element.value || "";
      if (value.trim()) return value;
      if (element.type === "submit") return "Submit";
      if (element.type === "reset") return "Reset";
      return element.getAttribute("title") || "";
    }
    if (tagName === "INPUT" && element.type === "file") {
      options.visited.add(element);
      const labels = element.labels || [];
      if (labels.length && !options.embeddedInLabelledBy) return roleGetAccessibleNameFromAssociatedLabels(labels, options);
      return "Choose File";
    }
    if (tagName === "INPUT" && element.type === "image") {
      options.visited.add(element);
      const labels = element.labels || [];
      if (labels.length && !options.embeddedInLabelledBy) return roleGetAccessibleNameFromAssociatedLabels(labels, options);
      const alt = element.getAttribute("alt") || "";
      if (alt.trim()) return alt;
      const title = element.getAttribute("title") || "";
      if (title.trim()) return title;
      return "Submit";
    }
    if (!labelledBy && tagName === "BUTTON") {
      options.visited.add(element);
      const labels = element.labels || [];
      if (labels.length) return roleGetAccessibleNameFromAssociatedLabels(labels, options);
    }
    if (!labelledBy && tagName === "OUTPUT") {
      options.visited.add(element);
      const labels = element.labels || [];
      if (labels.length) return roleGetAccessibleNameFromAssociatedLabels(labels, options);
      return element.getAttribute("title") || "";
    }
    if (!labelledBy && (tagName === "TEXTAREA" || tagName === "SELECT" || tagName === "INPUT" || tagName === "METER" || tagName === "PROGRESS")) {
      options.visited.add(element);
      const labels = element.labels || [];
      if (labels.length) return roleGetAccessibleNameFromAssociatedLabels(labels, options);
      const usePlaceholder = (tagName === "INPUT" && ["text", "password", "number", "search", "tel", "email", "url"].includes(element.type)) || tagName === "TEXTAREA";
      const placeholder = element.getAttribute("placeholder") || "";
      const title = element.getAttribute("title") || "";
      if (!usePlaceholder || title) return title;
      return placeholder;
    }
    if (!labelledBy && tagName === "FIELDSET") {
      options.visited.add(element);
      for (let child = element.firstElementChild; child; child = child.nextElementSibling) {
        if (roleElementSafeTagName(child) === "LEGEND") {
          return roleTextAlternative(child, {
            ...childOptions,
            embeddedInNativeTextAlternative: { element: child, hidden: roleElementHiddenForAria(child) },
          });
        }
      }
      return element.getAttribute("title") || "";
    }
    if (!labelledBy && tagName === "FIGURE") {
      options.visited.add(element);
      for (let child = element.firstElementChild; child; child = child.nextElementSibling) {
        if (roleElementSafeTagName(child) === "FIGCAPTION") {
          return roleTextAlternative(child, {
            ...childOptions,
            embeddedInNativeTextAlternative: { element: child, hidden: roleElementHiddenForAria(child) },
          });
        }
      }
      return element.getAttribute("title") || "";
    }
    if (tagName === "IMG") {
      options.visited.add(element);
      const alt = element.getAttribute("alt") || "";
      if (alt.trim()) return alt;
      return element.getAttribute("title") || "";
    }
    if (tagName === "TABLE") {
      options.visited.add(element);
      for (let child = element.firstElementChild; child; child = child.nextElementSibling) {
        if (roleElementSafeTagName(child) === "CAPTION") {
          return roleTextAlternative(child, {
            ...childOptions,
            embeddedInNativeTextAlternative: { element: child, hidden: roleElementHiddenForAria(child) },
          });
        }
      }
      const summary = element.getAttribute("summary") || "";
      if (summary) return summary;
    }
    if (tagName === "AREA") {
      options.visited.add(element);
      const alt = element.getAttribute("alt") || "";
      if (alt.trim()) return alt;
      return element.getAttribute("title") || "";
    }
    if (tagName === "SVG" || element.ownerSVGElement) {
      options.visited.add(element);
      for (let child = element.firstElementChild; child; child = child.nextElementSibling) {
        if (roleElementSafeTagName(child) === "TITLE" && child.ownerSVGElement) {
          return roleTextAlternative(child, {
            ...childOptions,
            embeddedInLabelledBy: { element: child, hidden: roleElementHiddenForAria(child) },
          });
        }
      }
    }
    if (element.ownerSVGElement && tagName === "A") {
      const svgTitle = element.getAttribute("xlink:title") || "";
      if (svgTitle.trim()) {
        options.visited.add(element);
        return svgTitle;
      }
    }
  }
  const shouldNameFromContentForSummary = tagName === "SUMMARY" && !["presentation", "none"].includes(role);
  if (roleAllowsNameFromContent(role, options.embeddedInTargetElement === "descendant") || shouldNameFromContentForSummary || !!options.embeddedInLabelledBy || !!options.embeddedInDescribedBy || !!options.embeddedInLabel || !!options.embeddedInNativeTextAlternative) {
    options.visited.add(element);
    const accessibleName = roleInnerAccumulatedText(element, childOptions);
    const maybeTrimmed = options.embeddedInTargetElement === "self" ? accessibleName.trim() : accessibleName;
    if (maybeTrimmed) return maybeTrimmed;
  }
  if (!["presentation", "none"].includes(role) || tagName === "IFRAME" || tagName === "FRAME") {
    options.visited.add(element);
    const title = element.getAttribute("title") || "";
    if (title.trim()) return title;
  }
  options.visited.add(element);
  return "";
}

function roleGetAccessibleNameFromAssociatedLabels(labels, options) {
  return [...labels].map((label) => roleTextAlternative(label, {
    ...options,
    embeddedInLabel: { element: label, hidden: roleElementHiddenForAria(label) },
    embeddedInNativeTextAlternative: undefined,
    embeddedInLabelledBy: undefined,
    embeddedInDescribedBy: undefined,
    embeddedInTargetElement: undefined,
  })).filter((text) => !!text).join(" ");
}

function roleGetElementAccessibleNameText(element, includeHidden) {
  const cache = includeHidden ? roleAccessibleNameHiddenCache : roleAccessibleNameCache;
  let text = cache ? cache.get(element) : undefined;
  if (text === undefined) {
    text = roleAsFlatString(roleTextAlternative(element, {
      includeHidden,
      visited: new Set(),
      embeddedInTargetElement: "self",
    }));
    if (cache) cache.set(element, text);
  }
  return text;
}

function roleGetElementAccessibleDescription(element, includeHidden) {
  const cache = includeHidden ? roleAccessibleDescriptionHiddenCache : roleAccessibleDescriptionCache;
  let description = cache ? cache.get(element) : undefined;
  if (description === undefined) {
    description = "";
    if (element.hasAttribute("aria-describedby")) {
      const describedBy = roleGetIdRefs(element, element.getAttribute("aria-describedby"));
      description = roleAsFlatString(describedBy.map((ref) => roleTextAlternative(ref, {
        includeHidden,
        visited: new Set(),
        embeddedInDescribedBy: { element: ref, hidden: roleElementHiddenForAria(ref) },
      })).join(" "));
    } else if (element.hasAttribute("aria-description")) {
      description = roleAsFlatString(element.getAttribute("aria-description") || "");
    } else {
      description = roleAsFlatString(element.getAttribute("title") || "");
    }
    if (cache) cache.set(element, description);
  }
  return description;
}

// Generated content is part of the accessible name. Playwright reads the
// computed ::before/::after content, tokenizes it, and only accepts string
// tokens and `attr(<ident>)` functions, after an optional ` / ` alternative
// separator. Anything else yields no contribution, so an unsupported token
// stream is the same as an empty one.
function roleContentUnescape(source, index) {
  let i = index + 1;
  if (i >= source.length) return { value: "", next: i };
  if (source[i] === "\n" || source[i] === "\r" || source[i] === "\f") return { value: "", next: i + 1 };
  let hex = "";
  while (i < source.length && hex.length < 6 && /[0-9a-fA-F]/.test(source[i])) {
    hex += source[i];
    i++;
  }
  if (hex) {
    if (i < source.length && /\s/.test(source[i])) i++;
    let code = parseInt(hex, 16);
    if (code === 0 || (code >= 0xd800 && code <= 0xdfff) || code > 0x10ffff) code = 0xfffd;
    return { value: String.fromCodePoint(code), next: i };
  }
  return { value: source[i], next: i + 1 };
}

function roleIsIdentChar(char, first) {
  if (char === undefined) return false;
  if (char === "-" || char === "_") return true;
  if (char >= "0" && char <= "9") return !first;
  return char >= "\x80" || (char >= "A" && char <= "Z") || (char >= "a" && char <= "z");
}

function roleContentIdent(source, index) {
  let i = index;
  let value = "";
  while (i < source.length) {
    const char = source[i];
    if (char === "\\") {
      const unescaped = roleContentUnescape(source, i);
      value += unescaped.value;
      i = unescaped.next;
      continue;
    }
    if (!roleIsIdentChar(char, i === index)) break;
    value += char;
    i++;
  }
  return { value, next: i };
}

function roleContentTokens(source) {
  const tokens = [];
  let i = 0;
  while (i < source.length) {
    matcherStep();
    const char = source[i];
    if (/\s/.test(char)) {
      while (i < source.length && /\s/.test(source[i])) i++;
      continue;
    }
    if (char === '"' || char === "'") {
      const quote = char;
      i++;
      let value = "";
      let closed = false;
      while (i < source.length) {
        const current = source[i];
        if (current === quote) {
          i++;
          closed = true;
          break;
        }
        if (current === "\\") {
          const unescaped = roleContentUnescape(source, i);
          value += unescaped.value;
          i = unescaped.next;
          continue;
        }
        if (current === "\n" || current === "\r" || current === "\f") break;
        value += current;
        i++;
      }
      if (!closed) return null;
      tokens.push({ type: "string", value });
      continue;
    }
    if (char === "/") {
      tokens.push({ type: "delim", value: "/" });
      i++;
      continue;
    }
    if (char === "(") {
      tokens.push({ type: "open" });
      i++;
      continue;
    }
    if (char === ")") {
      tokens.push({ type: "close" });
      i++;
      continue;
    }
    if (char === "\\" || roleIsIdentChar(char, true)) {
      const ident = roleContentIdent(source, i);
      if (!ident.value) return null;
      i = ident.next;
      if (i < source.length && source[i] === "(") {
        tokens.push({ type: "function", value: ident.value });
        i++;
      } else {
        tokens.push({ type: "ident", value: ident.value });
      }
      continue;
    }
    return null;
  }
  return tokens;
}

function roleParseCSSContent(element, content, isPseudo) {
  if (!content || content === "none" || content === "normal") return undefined;
  const all = roleContentTokens(content);
  if (all === null) return undefined;
  let tokens = all;
  const slash = tokens.findIndex((token) => token.type === "delim" && token.value === "/");
  if (slash !== -1) tokens = tokens.slice(slash + 1);
  else if (!isPseudo) return undefined;
  const accumulated = [];
  let index = 0;
  while (index < tokens.length) {
    const token = tokens[index];
    if (token.type === "string") {
      accumulated.push(token.value);
      index++;
    } else if (token.type === "function" && token.value === "attr" && tokens[index + 1] && tokens[index + 1].type === "ident" && tokens[index + 2] && tokens[index + 2].type === "close") {
      accumulated.push(element.getAttribute(tokens[index + 1].value) || "");
      index += 3;
    } else {
      return undefined;
    }
  }
  return accumulated.join("");
}

function roleGetCSSContent(element, pseudo) {
  const cache = pseudo === "::before" ? rolePseudoBeforeCache : pseudo === "::after" ? rolePseudoAfterCache : rolePseudoContentCache;
  if (cache && cache.has(element)) return cache.get(element);
  const style = roleGetStyle(element, pseudo);
  let content;
  if (style) {
    const contentValue = style.content;
    if (contentValue && contentValue !== "none" && contentValue !== "normal") {
      if (style.display !== "none" && style.visibility !== "hidden") content = roleParseCSSContent(element, contentValue, !!pseudo);
    }
  }
  if (pseudo && content !== undefined) {
    const display = (style && style.display) || "inline";
    if (display !== "inline") content = " " + content + " ";
  }
  if (cache) cache.set(element, content);
  return content;
}

// The typed body parser. It is Playwright's `parseAttributeSelector` with the
// same errors collapsed to the native invalid-locator sentinel.
function roleParseAttributeSelector(source) {
  let wp = 0;
  let EOL = source.length === 0;
  const next = () => source[wp] || "";
  const eat = () => {
    const result = next();
    ++wp;
    EOL = wp >= source.length;
    return result;
  };
  const syntaxError = () => {
    throw invalidSelector;
  };
  function skipSpaces() {
    while (!EOL && /\s/.test(next())) eat();
  }
  function isCSSNameChar(char) {
    return char >= "\x80" || char >= "0" && char <= "9" || char >= "A" && char <= "Z" || char >= "a" && char <= "z" || char === "_" || char === "-";
  }
  function readIdentifier() {
    let result = "";
    skipSpaces();
    while (!EOL && isCSSNameChar(next())) result += eat();
    return result;
  }
  function readQuotedString(quote) {
    let result = eat();
    if (result !== quote) syntaxError();
    while (!EOL && next() !== quote) {
      if (next() === "\\") eat();
      result += eat();
    }
    if (next() !== quote) syntaxError();
    result += eat();
    return result;
  }
  function readRegularExpression() {
    if (eat() !== "/") syntaxError();
    let source = "";
    let inClass = false;
    while (!EOL) {
      if (next() === "\\") {
        source += eat();
        if (EOL) syntaxError();
      } else if (inClass && next() === "]") {
        inClass = false;
      } else if (!inClass && next() === "[") {
        inClass = true;
      } else if (!inClass && next() === "/") {
        break;
      }
      source += eat();
    }
    if (eat() !== "/") syntaxError();
    let flags = "";
    while (!EOL && next().match(/[dgimsuvy]/)) flags += eat();
    try {
      return new RegExp(source, flags);
    } catch (error) {
      throw invalidSelector;
    }
  }
  function readAttributeToken() {
    skipSpaces();
    let token;
    if (next() === "'" || next() === '"') token = readQuotedString(next()).slice(1, -1);
    else token = readIdentifier();
    if (!token) syntaxError();
    return token;
  }
  function readOperator() {
    skipSpaces();
    let op = "";
    if (!EOL) op += eat();
    if (!EOL && op !== "=") op += eat();
    if (!["=", "*=", "^=", "$=", "|=", "~="].includes(op)) syntaxError();
    return op;
  }
  function readAttribute() {
    eat();
    const jsonPath = [readAttributeToken()];
    skipSpaces();
    while (next() === ".") {
      eat();
      jsonPath.push(readAttributeToken());
      skipSpaces();
    }
    if (next() === "]") {
      eat();
      return { name: jsonPath.join("."), jsonPath, op: "<truthy>", value: null, caseSensitive: false };
    }
    const operator = readOperator();
    let value;
    let caseSensitive = true;
    skipSpaces();
    if (next() === "/") {
      if (operator !== "=") syntaxError();
      value = readRegularExpression();
    } else if (next() === "'" || next() === '"') {
      value = readQuotedString(next()).slice(1, -1);
      skipSpaces();
      if (next() === "i" || next() === "I") {
        caseSensitive = false;
        eat();
      } else if (next() === "s" || next() === "S") {
        caseSensitive = true;
        eat();
      }
    } else {
      value = "";
      while (!EOL && (isCSSNameChar(next()) || next() === "+" || next() === ".")) value += eat();
      if (value === "true") value = true;
      else if (value === "false") value = false;
    }
    skipSpaces();
    if (next() !== "]") syntaxError();
    eat();
    if (operator !== "=" && typeof value !== "string") syntaxError();
    return { name: jsonPath.join("."), jsonPath, op: operator, value, caseSensitive };
  }
  const result = { name: "", attributes: [] };
  result.name = readIdentifier();
  skipSpaces();
  while (next() === "[") {
    result.attributes.push(readAttribute());
    skipSpaces();
  }
  if (!EOL) syntaxError();
  if (!result.name && !result.attributes.length) syntaxError();
  return result;
}

function roleValidateSupportedRole(attr, roles, role) {
  if (!roles.includes(role)) throw invalidSelector;
}

function roleValidateSupportedValues(attr, values) {
  if (attr.op !== "<truthy>" && !values.includes(attr.value)) throw invalidSelector;
}

function roleValidateSupportedOp(attr, ops) {
  if (!ops.includes(attr.op)) throw invalidSelector;
}

function roleValidateAttributes(attributes, role) {
  const options = { role };
  for (const attr of attributes) {
    switch (attr.name) {
      case "checked": {
        roleValidateSupportedRole(attr.name, roleAriaCheckedRoles, role);
        roleValidateSupportedValues(attr, [true, false, "mixed"]);
        roleValidateSupportedOp(attr, ["<truthy>", "="]);
        options.checked = attr.op === "<truthy>" ? true : attr.value;
        break;
      }
      case "pressed": {
        roleValidateSupportedRole(attr.name, roleAriaPressedRoles, role);
        roleValidateSupportedValues(attr, [true, false, "mixed"]);
        roleValidateSupportedOp(attr, ["<truthy>", "="]);
        options.pressed = attr.op === "<truthy>" ? true : attr.value;
        break;
      }
      case "selected": {
        roleValidateSupportedRole(attr.name, roleAriaSelectedRoles, role);
        roleValidateSupportedValues(attr, [true, false]);
        roleValidateSupportedOp(attr, ["<truthy>", "="]);
        options.selected = attr.op === "<truthy>" ? true : attr.value;
        break;
      }
      case "expanded": {
        roleValidateSupportedRole(attr.name, roleAriaExpandedRoles, role);
        roleValidateSupportedValues(attr, [true, false]);
        roleValidateSupportedOp(attr, ["<truthy>", "="]);
        options.expanded = attr.op === "<truthy>" ? true : attr.value;
        break;
      }
      case "level": {
        roleValidateSupportedRole(attr.name, roleAriaLevelRoles, role);
        if (typeof attr.value === "string") attr.value = +attr.value;
        if (attr.op !== "=" || typeof attr.value !== "number" || Number.isNaN(attr.value)) throw invalidSelector;
        options.level = attr.value;
        break;
      }
      case "disabled": {
        roleValidateSupportedValues(attr, [true, false]);
        roleValidateSupportedOp(attr, ["<truthy>", "="]);
        options.disabled = attr.op === "<truthy>" ? true : attr.value;
        break;
      }
      case "name": {
        if (attr.op === "<truthy>") throw invalidSelector;
        if (typeof attr.value !== "string" && !(attr.value instanceof RegExp)) throw invalidSelector;
        options.name = attr.value;
        options.nameOp = attr.op;
        options.nameExact = attr.caseSensitive;
        break;
      }
      case "description": {
        if (attr.op === "<truthy>") throw invalidSelector;
        if (typeof attr.value !== "string" && !(attr.value instanceof RegExp)) throw invalidSelector;
        options.description = attr.value;
        options.descriptionOp = attr.op;
        options.descriptionExact = attr.caseSensitive;
        break;
      }
      case "include-hidden": {
        roleValidateSupportedValues(attr, [true, false]);
        roleValidateSupportedOp(attr, ["<truthy>", "="]);
        options.includeHidden = attr.op === "<truthy>" ? true : attr.value;
        break;
      }
      default:
        throw invalidSelector;
    }
  }
  return options;
}

function roleMatchesAttributePart(value, attr) {
  const objValue = typeof value === "string" && !attr.caseSensitive ? value.toUpperCase() : value;
  const attrValue = typeof attr.value === "string" && !attr.caseSensitive ? attr.value.toUpperCase() : attr.value;
  if (attr.op === "<truthy>") return !!objValue;
  if (attr.op === "=") {
    if (attrValue instanceof RegExp) {
      attrValue.lastIndex = 0;
      return typeof objValue === "string" && !!objValue.match(attrValue);
    }
    return objValue === attrValue;
  }
  if (typeof objValue !== "string" || typeof attrValue !== "string") return false;
  if (attr.op === "*=") return objValue.includes(attrValue);
  if (attr.op === "^=") return objValue.startsWith(attrValue);
  if (attr.op === "$=") return objValue.endsWith(attrValue);
  if (attr.op === "|=") return objValue === attrValue || objValue.startsWith(attrValue + "-");
  if (attr.op === "~=") return objValue.split(" ").includes(attrValue);
  return false;
}

function roleQuery(scope, options, internal) {
  const result = [];
  const match = (element) => {
    matcherStep();
    if (roleGetAriaRole(element) !== options.role) return;
    if (options.selected !== undefined && roleGetAriaSelected(element) !== options.selected) return;
    if (options.checked !== undefined && roleGetAriaChecked(element) !== options.checked) return;
    if (options.pressed !== undefined && roleGetAriaPressed(element) !== options.pressed) return;
    if (options.expanded !== undefined && roleGetAriaExpanded(element) !== options.expanded) return;
    if (options.level !== undefined && roleGetAriaLevel(element) !== options.level) return;
    if (options.disabled !== undefined && roleGetAriaDisabled(element) !== options.disabled) return;
    if (!options.includeHidden && roleElementHiddenForAria(element)) return;
    if (options.name !== undefined) {
      const accessibleName = roleNormalizeWhiteSpace(roleGetElementAccessibleNameText(element, !!options.includeHidden));
      if (typeof options.name === "string") options.name = roleNormalizeWhiteSpace(options.name);
      if (internal && !options.nameExact && options.nameOp === "=") options.nameOp = "*=";
      if (!roleMatchesAttributePart(accessibleName, { name: "", jsonPath: [], op: options.nameOp || "=", value: options.name, caseSensitive: !!options.nameExact })) return;
    }
    if (options.description !== undefined) {
      const accessibleDescription = roleNormalizeWhiteSpace(roleGetElementAccessibleDescription(element, !!options.includeHidden));
      if (typeof options.description === "string") options.description = roleNormalizeWhiteSpace(options.description);
      if (internal && !options.descriptionExact && options.descriptionOp === "=") options.descriptionOp = "*=";
      if (!roleMatchesAttributePart(accessibleDescription, { name: "", jsonPath: [], op: options.descriptionOp || "=", value: options.description, caseSensitive: !!options.descriptionExact })) return;
    }
    result.push(element);
  };
  const query = (root, depth) => {
    matcherStep();
    if (depth > 256) throw matcherLimit;
    const shadows = [];
    if (root.shadowRoot) shadows.push(root.shadowRoot);
    for (const element of root.querySelectorAll("*")) {
      matcherStep();
      match(element);
      if (element.shadowRoot) shadows.push(element.shadowRoot);
    }
    for (const shadow of shadows) {
      matcherStep();
      query(shadow, depth + 1);
    }
  };
  query(scope, 0);
  return result;
}

function roleQueryAll(scope, body, internal = false) {
  const parsed = roleParseAttributeSelector(body);
  const role = parsed.name.toLowerCase();
  if (!role) throw invalidSelector;
  const options = roleValidateAttributes(parsed.attributes, role);
  roleBeginCaches();
  try {
    return roleQuery(scope, options, internal);
  } finally {
    roleEndCaches();
  }
}
