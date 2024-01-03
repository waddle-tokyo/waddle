import type * as api from "../defs.js";

export type Request = {
	/**
	 * A `requestID` is used to deduplicate multiple `createConversation`
	 * requests by the same user.
	 */
	requestID: string,

	/**
	 * The kind of conversation.
	 *
	 * `"unique"` groups support only 2 participants
	 * (the requester and one element in `otherParticipants`).
	 * This API will return an existing `"unique"` group, rather than create a
	 * new one, if a `"unique"` conversation with the same participants already
	 * exists.
	 */
	kind: "group" | "unique",

	/**
	 * The other users that will be added to the conversation.
	 *
	 * The requesting user is also added to the conversation.
	 *
	 * Each participant must have at least one registered conversation key.
	 */
	otherParticipants: api.UserID[],
};

export type Response = {
	conversationID: string,
};
