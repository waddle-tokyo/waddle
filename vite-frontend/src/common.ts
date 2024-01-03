export function getTagById<T extends keyof HTMLElementTagNameMap>(id: string, tag: T): HTMLElementTagNameMap[T] {
	const element = document.getElementById(id);
	if (!element) {
		throw new Error(`tag ${tag} of id (${id}) does not exist`);
	}
	if (element.tagName === tag.toUpperCase()) {
		return element as HTMLElementTagNameMap[T];
	}
	throw new Error(`element with id (${id}) does not have tag ${tag} but instead ${element.tagName}`);
}
