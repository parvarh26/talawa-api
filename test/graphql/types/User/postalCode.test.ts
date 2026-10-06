import { faker } from "@faker-js/faker";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GraphQLContext } from "~/src/graphql/context";
import { postalCodeResolver } from "~/src/graphql/types/User/postalCode";
import type { User as UserType } from "~/src/graphql/types/User/User";
import { TalawaGraphQLError } from "~/src/utilities/TalawaGraphQLError";
import { createMockGraphQLContext } from "../../../_Mocks_/mockContextCreator/mockContextCreator";

describe("User field postalCode resolver (unit)", () => {
	let ctx: GraphQLContext;
	let mocks: ReturnType<typeof createMockGraphQLContext>["mocks"];
	let currentUserId: string;
	let parent: UserType;

	beforeEach(() => {
		currentUserId = faker.string.ulid();
		const { context, mocks: newMocks } = createMockGraphQLContext(
			true,
			currentUserId,
		);
		ctx = context;
		mocks = newMocks;

		parent = {
			id: currentUserId,
			name: "Test User",
			emailAddress: "test@example.com",
			isEmailAddressVerified: true,
			role: "regular",
			postalCode: "10001",
			creatorId: null,
			createdAt: new Date("2025-01-01T10:00:00Z"),
			updatedAt: null,
			updaterId: null,
		} as UserType; // partial UserType for testing
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("throws unauthenticated error when client is not authenticated", async () => {
		const { context: unauthCtx } = createMockGraphQLContext(false);

		await expect(postalCodeResolver(parent, {}, unauthCtx)).rejects.toThrow(
			expect.objectContaining({
				extensions: expect.objectContaining({ code: "unauthenticated" }),
			}),
		);
	});

	it("throws unauthenticated error when authenticated user does not exist in database", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue(undefined);

		await expect(postalCodeResolver(parent, {}, ctx)).rejects.toThrow(
			expect.objectContaining({
				extensions: expect.objectContaining({ code: "unauthenticated" }),
			}),
		);
	});

	it("throws unauthorized_action when non-admin accesses another user's postalCode", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue({
			role: "regular",
		});

		const anotherUser = {
			...parent,
			id: faker.string.ulid(),
		} as UserType; // partial UserType for testing

		await expect(postalCodeResolver(anotherUser, {}, ctx)).rejects.toThrow(
			expect.objectContaining({
				extensions: expect.objectContaining({ code: "unauthorized_action" }),
			}),
		);
	});

	it("returns escaped postalCode when user accesses own data", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue({
			role: "regular",
		});

		const result = await postalCodeResolver(parent, {}, ctx);

		expect(result).toBe("10001");
	});

	it("returns null when postalCode is null", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue({
			role: "regular",
		});

		const parentWithNull = {
			...parent,
			postalCode: null,
		} as UserType; // partial UserType for testing

		const result = await postalCodeResolver(parentWithNull, {}, ctx);

		expect(result).toBeNull();
	});

	it("returns null when postalCode is undefined", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue({
			role: "regular",
		});

		const parentWithUndefined = {
			...parent,
			postalCode: undefined,
		} as unknown as UserType; // partial UserType for testing

		const result = await postalCodeResolver(parentWithUndefined, {}, ctx);

		expect(result).toBeNull();
	});

	it("returns escaped postalCode when admin accesses another user's data", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue({
			role: "administrator",
		});

		const anotherUser = {
			...parent,
			id: faker.string.ulid(),
			postalCode: "90210",
		} as UserType; // partial UserType for testing

		const result = await postalCodeResolver(anotherUser, {}, ctx);

		expect(result).toBe("90210");
	});

	it("escapes HTML characters in postalCode to prevent XSS", async () => {
		mocks.drizzleClient.query.usersTable.findFirst.mockResolvedValue({
			role: "regular",
		});

		const parentWithHtml = {
			...parent,
			postalCode: "<script>alert('xss')</script>",
		} as UserType; // partial UserType for testing

		const result = await postalCodeResolver(parentWithHtml, {}, ctx);

		expect(result).not.toContain("<script>");
		expect(result).toContain("&lt;script&gt;");
	});

	it("rethrows TalawaGraphQLError without logging", async () => {
		const talawaError = new TalawaGraphQLError({
			extensions: { code: "unauthenticated" },
		});

		mocks.drizzleClient.query.usersTable.findFirst.mockRejectedValue(
			talawaError,
		);

		await expect(postalCodeResolver(parent, {}, ctx)).rejects.toBe(
			talawaError,
		);

		expect(ctx.log.error).not.toHaveBeenCalled();
	});

	it("logs and wraps unknown errors as unexpected", async () => {
		const unknownError = new Error("DB crash");

		mocks.drizzleClient.query.usersTable.findFirst.mockRejectedValue(
			unknownError,
		);

		await expect(postalCodeResolver(parent, {}, ctx)).rejects.toThrow(
			expect.objectContaining({
				extensions: expect.objectContaining({ code: "unexpected" }),
			}),
		);

		expect(ctx.log.error).toHaveBeenCalledWith(unknownError);
	});
});
