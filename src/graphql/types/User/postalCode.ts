import type { GraphQLContext } from "~/src/graphql/context";
import envConfig from "~/src/utilities/graphqLimits";
import { escapeHTML } from "~/src/utilities/sanitizer";
import { TalawaGraphQLError } from "~/src/utilities/TalawaGraphQLError";
import type { User as UserType } from "./User";
import { User } from "./User";

/**
 * Resolver for the `postalCode` field on the `User` type.
 * Enforces authentication, database lookup, and authorization rules before returning the escaped postal code.
 *
 * @param parent - The parent `User` object containing the raw postalCode.
 * @param _args - The GraphQL arguments for the field (unused).
 * @param ctx - The GraphQL context containing the current client and Drizzle client.
 * @returns The HTML-escaped postalCode string, or null if not set.
 * @throws {TalawaGraphQLError} if the client is unauthenticated or unauthorized.
 */
export const postalCodeResolver = async (
	parent: UserType,
	_args: Record<string, never> | unknown,
	ctx: GraphQLContext,
): Promise<string | null> => {
	if (!ctx.currentClient.isAuthenticated) {
		throw new TalawaGraphQLError({
			extensions: {
				code: "unauthenticated",
			},
		});
	}

	const currentUserId = ctx.currentClient.user.id;

	try {
		const currentUser = await ctx.drizzleClient.query.usersTable.findFirst({
			columns: {
				role: true,
			},
			where: (fields, operators) => operators.eq(fields.id, currentUserId),
		});

		if (currentUser === undefined) {
			throw new TalawaGraphQLError({
				extensions: {
					code: "unauthenticated",
				},
			});
		}

		if (
			currentUser.role !== "administrator" &&
			parent.id !== currentUserId
		) {
			throw new TalawaGraphQLError({
				extensions: {
					code: "unauthorized_action",
				},
			});
		}

		return parent.postalCode ? escapeHTML(parent.postalCode) : null;
	} catch (error) {
		if (error instanceof TalawaGraphQLError) {
			throw error;
		}

		ctx.log.error(error);
		throw new TalawaGraphQLError({
			message: "Internal server error",
			extensions: {
				code: "unexpected",
			},
		});
	}
};

User.implement({
	fields: (t) => ({
		postalCode: t.field({
			description: "Postal code of the user.",
			complexity: envConfig.API_GRAPHQL_SCALAR_RESOLVER_FIELD_COST,
			nullable: true,
			resolve: postalCodeResolver,
			type: "String",
		}),
	}),
});
