// A positive result is useful only when the same protected global projection
// also finds each named receiver uniquely. Local samples grant no authority.
function sampleForm(nodes, capture, project) {
    if (nodes.length > 4096 || document.hidden || !Element.prototype.checkVisibility) return project();
    const entries = new Map();
    const forms = new Map();
    function state(element, metadata) {
        const proof = metadata?.replayForm;
        if (!proof) return;
        if (!(element instanceof HTMLElement) || !element.isConnected ||
            element.getRootNode() !== document || element.assignedSlot ||
            element.closest('[inert],[hidden],[aria-disabled="true"],[aria-busy="true"],[contenteditable]') ||
            element.matches(':disabled') || !element.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return;
        const form = element.closest('form');
        if (!(form instanceof HTMLFormElement) || form.hasAttribute('aria-busy')) return;
        const control = element instanceof HTMLLabelElement ? element.control : element;
        if (!control || control.form !== form || control.matches(':disabled')) return;
        let kind;
        if (element instanceof HTMLLabelElement && control instanceof HTMLInputElement &&
            control.type === 'radio' && element.contains(control) && element.querySelectorAll('input').length === 1) kind = 'radio';
        else if (element instanceof HTMLButtonElement) kind = 'button';
        else if (element instanceof HTMLInputElement && element.type === 'text' && typeof metadata.value === 'string' && metadata.value.length <= 512) kind = 'field';
        else return;
        const box = element.getBoundingClientRect();
        if (box.width <= 0 || box.height <= 0) return;
        if (kind !== proof.kind || form !== nodes[proof.owner] || control !== nodes[proof.control]) return;
        return { kind, form, control, value: kind === 'field' ? metadata.value : undefined, x: box.x, y: box.y, width: box.width, height: box.height,
            checked: kind === 'radio' && control.checked, hovered: kind === 'radio' && element.matches(':hover') };
    }
    let inspected = 0;
    for (let i = 0; i < nodes.length; ++i) {
        const element = nodes[i];
        if (!(element instanceof HTMLLabelElement || element instanceof HTMLButtonElement ||
            element instanceof HTMLInputElement) || !element.closest('form')) continue;
        if (++inspected > 64) return project();
        const sample = state(element, capture(element, i));
        if (!sample) continue;
        if (entries.size >= 32 || entries.has(element)) return project();
        entries.set(element, sample);
        let kinds = forms.get(sample.form);
        if (!kinds) forms.set(sample.form, kinds = new Set());
        kinds.add(sample.kind);
    }
    if (![...forms.values()].some(kinds => kinds.size === 3)) return project();
    const href = location.href, width = innerWidth, height = innerHeight;
    let changed = false;
    const observer = new MutationObserver(() => { changed = true; });
    observer.observe(document, { childList: true, subtree: true, attributes: true, characterData: true });
    const start = performance.now();
    return new Promise(resolve => setTimeout(resolve, 76)).then(() => {
        const unchanged = !changed && observer.takeRecords().length === 0;
        observer.disconnect();
        // The canonical metadata batch is synchronous. Never resume it with
        // document or security inventory from before a mutation or navigation.
        if (!unchanged || document.hidden || location.href !== href || innerWidth !== width ||
            innerHeight !== height) return { replaySampleChanged: true };
        if (performance.now() - start < 75) return project();
        return project((element, metadata) => {
            const proof = metadata.replayForm;
            const previous = entries.get(element);
            if (!previous || previous.kind !== proof.kind || forms.get(previous.form)?.size !== 3 ||
                previous.form !== nodes[proof.owner] || previous.control !== nodes[proof.control]) return false;
            const current = state(element, metadata);
            return !!current && current.form === previous.form && current.control === previous.control &&
                current.kind === previous.kind && current.value === previous.value && current.checked === previous.checked && current.hovered === previous.hovered &&
                current.x === previous.x && current.y === previous.y &&
                current.width === previous.width && current.height === previous.height;
        });
    });
}
