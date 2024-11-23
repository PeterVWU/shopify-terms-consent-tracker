/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.toml`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

interface ConsentRecord {
	cart_token: string;
	customer_email: string;
	ip_address: string;
	terms_version: string;
	timestamp: string;
	shop_domain: string;
}

interface ShopifyOrderWebhook {
	id: number;
	cart_token: string;
	shop_domain: string;
	order_number: string;
	customer: {
		email: string;
	};
}

interface Env {
	DB: D1Database;
	// Format for tokens: SHOP_TOKEN_[shop_domain_without_dots]
	// Format for secrets: SHOP_SECRET_[shop_domain_without_dots]
	[key: string]: string | D1Database;
}

interface ShopifyOrderWebhook {
	id: number;
	cart_token: string;
	shop_domain: string;
	order_number: string;
	customer: {
		email: string;
	};
}

interface ShopifyOrderNote {
	data: {
		orderAddMetafields?: {
			userErrors: Array<{
				field: string[];
				message: string;
			}>;
		};
	};
}
export default {
	async fetch(request, env, ctx): Promise<Response> {
		try {
			const url = new URL(request.url);

			// Handle CORS preflight
			if (request.method === "OPTIONS") {
				return new Response(null, {
					headers: corsHeaders()
				});
			}

			if (request.method === "POST") {
				switch (url.pathname) {
					case "/record-consent":
						return await handleConsent(request, env);
					case "/webhooks/order":
						return await handleOrderWebhook(request, env);
					default:
						return new Response("Not found", { status: 404 });
				}
			}

			return new Response("Method not allowed", { status: 405 });
		} catch (error) {
			console.error("Worker error:", error);
			return new Response(
				JSON.stringify({ error: "Internal server error" }),
				{ status: 500 }
			);
		}
	},
} satisfies ExportedHandler<Env>;


async function handleConsent(request: Request, env: Env): Promise<Response> {
	try {
		const data: ConsentRecord = await request.json();
		const shop = data.shop_domain

		if (!shop) {
			return new Response(
				JSON.stringify({ error: "Missing shop domain" }),
				{ status: 401 }
			);
		}

		const requiredFields: (keyof ConsentRecord)[] = [
			'cart_token',
			'terms_version',
			'timestamp'
		];

		for (const field of requiredFields) {
			if (!data[field]) {
				return new Response(
					JSON.stringify({ error: `Missing required field: ${field}` }),
					{ status: 400 }
				);
			}
		}

		// Store consent record
		const stmt = env.DB.prepare(`
		INSERT INTO consent_records (
		  cart_token,
		  customer_email,
		  ip_address,
		  terms_version,
		  accepted_at,
		  shop_domain
		) VALUES (?, ?, ?, ?, ?, ?)
	  `);

		await stmt.bind(
			data.cart_token,
			data.customer_email,
			data.ip_address,
			data.terms_version,
			data.timestamp,
			shop
		).run();

		return new Response(
			JSON.stringify({ status: "success" }),
			{ headers: corsHeaders() }
		);

	} catch (error) {
		console.error("Consent handling error:", error);
		return new Response(
			JSON.stringify({ error: "Failed to record consent" }),
			{ status: 500, headers: corsHeaders() }
		);
	}
}

async function handleOrderWebhook(request: Request, env: Env): Promise<Response> {
	try {
		// Get shop domain from header
		const shop = request.headers.get('X-Shopify-Shop-Domain');
		if (!shop) {
			return new Response("Missing shop domain", { status: 401 });
		}

		// Verify webhook with shop-specific secret
		if (!await verifyWebhook(request.clone(), shop, env)) {
			return new Response("Invalid webhook signature", { status: 401 });
		}

		const orderData: ShopifyOrderWebhook = await request.json();

		// Find matching consent record
		const consentRecord = await env.DB.prepare(`
				SELECT * FROM consent_records 
				WHERE cart_token = ? 
				AND shop_domain = ?
				ORDER BY accepted_at DESC 
				LIMIT 1
			`)
			.bind(orderData.cart_token, shop)
			.first();

		if (consentRecord) {
			// Add order note via Shopify API
			await addOrderNote(
				shop,
				orderData.id,
				`Terms and Conditions v${consentRecord.terms_version} accepted at ${consentRecord.accepted_at}`,
				orderData.order_number,
				env
			);

			// Update consent record with order info
			await env.DB.prepare(`
				UPDATE consent_records 
				SET order_id = ?, order_number = ? 
				WHERE cart_token = ?
				`)
				.bind(
					orderData.id.toString(),
					orderData.order_number,
					orderData.cart_token
				)
				.run();
		}

		return new Response("OK");
	} catch (error) {
		console.error("Webhook handling error:", error);
		return new Response("Webhook processing failed", { status: 500 });
	}
}


async function verifyWebhook(request: Request, shop: string, env: Env): Promise<boolean> {
	const hmac = request.headers.get('X-Shopify-Hmac-Sha256');
	if (!hmac) return false;

	// Get the webhook secret for this specific shop
	const secretKey = `SHOP_SECRET_${shop.replace(/[.-]/g, '_').toUpperCase()}`;
	const secret = env[secretKey];

	if (!secret) {
		console.error(`No webhook secret found for shop: ${shop} (${secretKey})`);
		return false;
	}

	// Get the raw body
	const body = await request.text();

	// Convert secret to Uint8Array
	const encoder = new TextEncoder();
	const keyData = encoder.encode(secret as string);
	const message = encoder.encode(body);

	// Import the secret key
	const key = await crypto.subtle.importKey(
		'raw',
		keyData,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['verify']
	);

	// Decode the base64 hmac from the header
	const signatureBuffer = base64ToUint8Array(hmac);

	// Verify the signature
	return await crypto.subtle.verify(
		'HMAC',
		key,
		signatureBuffer,
		message
	);
}

function base64ToUint8Array(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function corsHeaders(): HeadersInit {
	return {
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Methods": "POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, X-Shopify-Shop-Domain",
		"Content-Type": "application/json"
	};
}

async function addOrderNote(
	shop: string,
	orderId: number,
	note: string,
	orderNumber: string,
	env: Env
): Promise<void> {
	try {
		// Convert shop domain to environment variable name
		// e.g., 'my-store.myshopify.com' becomes 'SHOP_TOKEN_MY_STORE_MYSHOPIFY_COM'
		const tokenKey = `SHOP_TOKEN_${shop.replace(/[.-]/g, '_').toUpperCase()}`;
		const accessToken = env[tokenKey];

		if (!accessToken) {
			throw new Error(`No access token found for shop: ${shop} (${tokenKey})`);
		}

		// GraphQL mutation to add order note
		const mutation = `
		mutation orderAddMetafields($input: [MetafieldsSetInput!]!) {
		  ordersUpdate(input: {
			id: "gid://shopify/Order/${orderId}",
			metafields: $input
		  }) {
			userErrors {
			  field
			  message
			}
		  }
		}
	  `;

		const variables = {
			input: [{
				namespace: "terms_and_conditions",
				key: "acceptance",
				type: "single_line_text_field",
				value: note
			}]
		};

		// Call Shopify GraphQL API
		const response = await fetch(`https://${shop}/admin/api/2024-01/graphql.json`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-Shopify-Access-Token': accessToken as string,
			},
			body: JSON.stringify({
				query: mutation,
				variables: variables
			})
		});

		if (!response.ok) {
			const errorText = await response.text();
			throw new Error(`Shopify API error: ${response.status} - ${errorText}`);
		}

		const result: ShopifyOrderNote = await response.json();

		if (result.data?.orderAddMetafields?.userErrors && result.data?.orderAddMetafields?.userErrors?.length > 0) {
			throw new Error(
				`Shopify GraphQL error: ${result.data.orderAddMetafields?.userErrors[0].message}`
			);
		}

		console.log(`Successfully added note to order ${orderNumber}`);

	} catch (error) {
		console.error(`Failed to add note to order ${orderNumber}:`, error);
		throw error;
	}
}