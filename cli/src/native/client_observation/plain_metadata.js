// Fast case of bounded METADATA for light-tree HTML wrappers without naming,
// form, editing or authored accessibility attributes. Unsupported shapes run
// the complete reader on the same receiver in the same synchronous call.
function plainMetadata(node, testId, protectedEditor, focused, batch) {
    const path = node instanceof SVGPathElement && !node.firstChild;
    if (!batch.clearDocument || batch.hasClosedDetails || protectedEditor || focused ||
        !(path || (node instanceof HTMLElement && batch.plainTags.has(node.localName))) ||
        Node.prototype.getRootNode.call(node) !== document || node.isContentEditable ||
        node.shadowRoot) return null;

    const attributes = {};
    for (const attribute of node.attributes) {
        const name = attribute.name;
        if (name === 'id' || name === 'class' || name === 'data-placeholder') {
            attributes[name] = attribute.value;
        } else if (name !== 'style' && !name.startsWith('data-') &&
            !(node.localName === 'td' && (name === 'rowspan' || name === 'colspan')) &&
            !(node.localName === 'col' && (name === 'width' || name === 'name' || name === 'span')) &&
            !(path && batch.drawingAttributes.has(name))) {
            return null;
        }
    }
    let depth = batch.depths.get(node);
    if (depth === undefined) {
        const chain = [];
        for (let parent = node; parent; parent = parent.parentElement) {
            depth = batch.depths.get(parent);
            if (depth !== undefined) break;
            chain.push(parent);
            if (chain.length > 257) return null;
        }
        depth ??= -1;
        while (chain.length) batch.depths.set(chain.pop(), ++depth);
    }
    if (depth > 256) return null;
    const style = batch.styleOf(node);
    const display = style.display;
    if (display === 'contents') return null;
    // METADATA checks the intrinsic connection and owner on every receiver.
    // A light root equal to the current Document proves both for an Element.
    const bounds = node.getBoundingClientRect();
    // An empty client-rect list always has all-zero bounds. Only that case
    // needs the second read to distinguish an empty element from a zero box.
    const rect = bounds.width || bounds.height || bounds.x || bounds.y || node.getClientRects().length ? bounds : null;
    const visible = !!rect && rect.width > 0 && rect.height > 0 &&
        node.checkVisibility({visibilityProperty:true,opacityProperty:false,contentVisibilityAuto:false});
    const inline = display.startsWith('inline') || display.startsWith('ruby');
    const suppress = display === 'none' || style.getPropertyValue('interactivity') === 'inert';
    const clickable = visible && style.cursor === 'pointer' &&
        !(node.parentElement && batch.styleOf(node.parentElement).cursor === 'pointer');
    const author = {tag:node.localName,nodeType:1};
    if (inline) author.inline = true;
    if (node.localName === 'a') author.action = true;
    if (suppress) author.suppress = true;
    if (visible) author.visible = true;
    if (clickable) author.clickable = true;
    if (style.contentVisibility === 'hidden') author.skipsContent = true;
    const result = {author, safePublicNameFromContent:false, labels:[], controlStates:{},
        attributes, states:{secure:false,hidden:!visible,focused:false,disabled:false}, inputPurpose:'none'};
    if (!path && !author.action && inline && !suppress && visible) result.handlerProbe = true;
    const marker = node.getAttribute(testId);
    if (marker !== null) result.testId = marker;
    if (node.id) result.selector = '#' + CSS.escape(node.id);
    else if (marker !== null) result.selector = '[' + CSS.escape(testId) + '=' + JSON.stringify(marker) + ']';
    if (rect) result.rect = {x:rect.x,y:rect.y,width:rect.width,height:rect.height};
    if (node.localName === 'td') {
        const role = node.closest('table')?.getAttribute('role');
        if (role != null) result.cellTableRole = role;
    }
    return result;
}
