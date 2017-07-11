class CreditCardNumberEntry : Gtk.Entry {
	public CreditCardNumberEntry() {
		//this.text = "4111 1111 1111 1111";

		this.set_input_purpose(Gtk.InputPurpose.DIGITS);
		this.placeholder_text = "XXXX XXXX XXXX XXXX";
		this.set_property("max-length", this.placeholder_text.length);

		GLib.Regex is_digit = null;
		try { is_digit =  new GLib.Regex("\\d+"); } catch (GLib.RegexError e) { stderr.printf("REGEX ERROR: %s\n", e.message); }

		var insert_text_signal = GLib.Signal.lookup("insert-text", this.get_type());
		var add_space = false;

		ulong insert_text = -1;
		insert_text = this.insert_text.connect((new_text, new_text_length, ref position) => {
			if (!is_digit.match(new_text, 0, null)) {
				GLib.Signal.stop_emission(this, insert_text_signal, 0);
				return;
			}

			if (this.cursor_position == this.buffer.text.length) {
				var num_numbers = 0;
				unichar c;
				for (int i = 0; this.buffer.text.get_next_char(ref i, out c);) {
					if (c != ' ') {
						num_numbers++;
					}
				}

				if (num_numbers != 0 && (num_numbers % 4) == 0) {
					position++;
					add_space = true;
				}
			}
		});

		this.insert_text.connect_after(() => {
			if (add_space) {
				add_space = false;
				GLib.SignalHandler.block(this, insert_text);
				this.insert_at_cursor(" ");
				GLib.SignalHandler.unblock(this, insert_text);
			}
		});

		ulong backspace_text = -1;
		backspace_text = this.backspace.connect(() => {
			var pos = this.cursor_position - 2;
			if (pos > -1 && this.buffer.text.@get(pos) == ' ') {
				GLib.SignalHandler.block(this, backspace_text);
				this.backspace();
				GLib.SignalHandler.unblock(this, backspace_text);
			}
		});
	}
}

class CreditCardExpiryEntry : Gtk.Entry {
	private GLib.Regex is_valid;

	public CreditCardExpiryEntry() {
		//this.text = "12/20";

		this.set_input_purpose(Gtk.InputPurpose.DIGITS);
		this.placeholder_text = "MM / YY";
		this.set_property("max-length", this.placeholder_text.length);

		try { this.is_valid = new GLib.Regex("[\\d/ ]+"); } catch (GLib.RegexError e) { stderr.printf("REGEX ERROR: %s\n", e.message); }
		var insert_text_signal = GLib.Signal.lookup("insert-text", this.get_type());
		ulong insert_text = -1;
		insert_text = this.insert_text.connect((new_text, new_text_length, ref position) => {
			if (!is_valid.match(new_text, 0, null)) {
				GLib.Signal.stop_emission(this, insert_text_signal, 0);
			}
		});
	}
}

class CreditCard : Gtk.Frame {
	private Gtk.Grid grid;

	private CreditCardNumberEntry number_entry;
	private CreditCardExpiryEntry expiry_entry;
	//private Gtk.CheckButton store_in_vault_button;

	private bool challenge_cvv;
	private Gtk.Entry cvv_entry;

	public string number { get { return this.number_entry.text; } }
	public string expiry { get { return this.expiry_entry.text; } }
	public string cvv { get { return this.cvv_entry.text; } }
	//public bool store_in_vault { get { return this.store_in_vault_button.active; } }

	public HashTable<string, string> parameters {
		owned get {
			var parameters = new HashTable<string, string>(str_hash, str_equal);
			parameters.insert("number", this.number_entry.text);
			parameters.insert("expiration_date", this.expiry_entry.text);
			if (this.challenge_cvv) parameters.insert("cvv", this.cvv_entry.text);
			return parameters;
		}
	}

	public CreditCard() {
		this.label = "Credit Card";
		this.number_entry = new CreditCardNumberEntry();
		this.expiry_entry = new CreditCardExpiryEntry();
		//this.store_in_vault_button = new Gtk.CheckButton();

		var box = new Gtk.Box(Gtk.Orientation.VERTICAL, 6);
		box.margin = 10;

		this.grid = new Gtk.Grid();
		this.grid.column_spacing = 12;
		this.grid.row_spacing = 6;
		this.grid.margin = 18;
		this.add(this.grid);

		var number_label = new Gtk.Label("Card Number");
		number_label.get_style_context().add_class("dim-label");
		number_label.xalign = (float)1.0;
		this.grid.attach(number_label, 0, 0);
		this.grid.attach(this.number_entry, 1, 0);

		var expiry_label = new Gtk.Label("Expiration Date");
		expiry_label.get_style_context().add_class("dim-label");
		expiry_label.xalign = (float)1.0;
		this.grid.attach(expiry_label, 0, 1);
		this.grid.attach(this.expiry_entry, 1, 1);

		//var store_in_vault_label = new Gtk.Label("Save Payment Method");
		//store_in_vault_label.get_style_context().add_class("dim-label");
		//store_in_vault_label.xalign = (float)1.0;
		//this.grid.attach(store_in_vault_label, 0, 2);
		//this.grid.attach(this.store_in_vault_button, 1, 2);
	}

	public void set_challenges(string[] challenges) {
		for (var i = 0; i < challenges.length; i++) {
			var y = i + 2;
			switch (challenges[i]) {
				case "cvv":
					this.grid.insert_row(y);
					this.challenge_cvv = true;
					var cvv_label = new Gtk.Label("CVV");
					cvv_label.get_style_context().add_class("dim-label");
					cvv_label.xalign = (float)1.0;
					this.grid.attach(cvv_label, 0, y);
					this.cvv_entry = new Gtk.Entry();
					this.grid.attach(this.cvv_entry, 1, y);
					break;

				default:
					stderr.printf("CreditCard: unknown challenge: %s\n", challenges[i]);
					break;
			}
		}
		this.grid.show_all();
	}

	public void show_error(string field, string message) {
		// TODO: show the message somewhere
		stdout.printf("%s: %s\n", field, message);
		switch (field) {
			case "number":
				this.number_entry.get_style_context().add_class("error");
				break;

			case "expirationYear":
			case "expirationMonth":
			case "expirationDate":
				this.expiry_entry.get_style_context().add_class("error");
				break;

			default:
				stdout.printf("CreditCard.showError(): unknown field: %s\n", field);
				break;
		}
	}

	public void clear_errors() {
		this.number_entry.get_style_context().remove_class("error");
		this.expiry_entry.get_style_context().remove_class("error");
	}
}

class CreditCardLogo {
	private static Gdk.Pixbuf src = null;

	private static Gdk.Pixbuf logo(int offset) throws Error {
		if (CreditCardLogo.src == null) {
			CreditCardLogo.src = new Gdk.Pixbuf.from_file("cards.png");
		}
		const int HEIGHT = 28;
		return new Gdk.Pixbuf.subpixbuf(CreditCardLogo.src, 0, HEIGHT * offset, CreditCardLogo.src.width, HEIGHT);
	}

	public static Gtk.Image discover() throws Error   { return new Gtk.Image.from_pixbuf(logo(0)); }
	public static Gtk.Image visa() throws Error       { return new Gtk.Image.from_pixbuf(logo(1)); }
	public static Gtk.Image mastercard() throws Error { return new Gtk.Image.from_pixbuf(logo(2)); }
	public static Gtk.Image jcb() throws Error        { return new Gtk.Image.from_pixbuf(logo(3)); }
	public static Gtk.Image amex() throws Error       { return new Gtk.Image.from_pixbuf(logo(4)); }
}

struct Sale {
	public string nonce;
	public string amount;
	//public bool store_in_vault;

	// There are a whole bunch of other things that can go here.
}

struct PaymentMethod {
	public string type;
	public string nonce;
	public string description;
	public bool is_default;

	// Payment-type-specific details.
	public string? card_type; // e.g. "Visa"
}

class Braintree {
	protected Soup.Session session; // TODO: don't keep this public
	protected Environment env;
	protected string merchant_id;
	protected string public_key;
	protected string private_key;

	protected bool initialized;
	protected string? authorization_fingerprint;
	protected string? client_api_url;

	public string[] challenges { get; private set; }
	public PaymentMethod[] payment_methods { get; private set; }
	public Gtk.RadioButton[] payment_method_buttons { get; set; }

	public ClientTokenGateway client_token { owned get { return new ClientTokenGateway(this); } }
	public TransactionGateway transaction { owned get { return new TransactionGateway(this); } }
	public string merchant_url { owned get { return this.env.base_url() + "/merchants/" + this.merchant_id; } }

	public Braintree(Environment env, string merchant_id, string public_key, string private_key) {
		this.session = new Soup.Session();
		this.env = env;
		this.merchant_id = merchant_id;
		this.public_key = public_key;
		this.private_key = private_key;
		this.initialized = false;

		// Handle request authentication.
		this.session.authenticate.connect((msg, auth, retrying) => {
			auth.authenticate(this.public_key, this.private_key);
		});
	}

	public async void init(string? customer_id) throws Error {
		var client_token = yield this.client_token.generate(customer_id);
		var parsed_client_token = (string)GLib.Base64.decode(client_token);

		var parser = new Json.Parser();
		parser.load_from_data(parsed_client_token);
		var root = parser.get_root().get_object();

		this.authorization_fingerprint = root.get_string_member("authorizationFingerprint");
		this.client_api_url = root.get_string_member("clientApiUrl");

		// Retrieve configuration, payment methods, etc.
		yield this.init_configuration();
		yield this.init_payment_methods();

		this.initialized = true;
	}

	/*
	 * Initialize client-side configuration. The most important piece of information here is the
	 * list of challenges that are set up in the merchant's gateway, e.g. CVV.
	 */
	protected async void init_configuration() throws Error {
		var uri = new Soup.URI(this.client_api_url + "/v1/configuration");
		uri.set_query_from_fields("authorizationFingerprint", this.authorization_fingerprint);

		// TODO: refactor this into a general client api execute?
		var parser = new Json.Parser();
		var msg = new Soup.Message("GET", uri.to_string(false));
		yield parser.load_from_stream_async(yield this.session.send_async(msg));
		var root = parser.get_root().get_object();

		if (msg.status_code != Soup.Status.OK) {
			throw new ApiError.UNEXPECTED_RESPONSE("Unexpected response: " + msg.status_code.to_string());
		}

		var challenges = root.get_array_member("challenges");
		this.challenges = new string[challenges.get_length()];
		challenges.foreach_element((ar, i, el) => {
			this.challenges[i] = el.get_string();
		});
	}

	protected async void init_payment_methods() throws Error {
		var uri = new Soup.URI(this.client_api_url + "/v1/payment_methods");
		uri.set_query_from_fields("authorizationFingerprint", this.authorization_fingerprint);

		var parser = new Json.Parser();
		var msg = new Soup.Message("GET", uri.to_string(false));

		//string response = yield this.read_whole_stream(yield this.session.send_async(msg));
		//stdout.printf("%s\n", response);

		yield parser.load_from_stream_async(yield this.session.send_async(msg));
		var root = parser.get_root().get_object();

		if (msg.status_code != Soup.Status.OK) {
			throw new ApiError.UNEXPECTED_RESPONSE("Unexpected response: " + msg.status_code.to_string());
		}

		var paymentMethods = root.get_array_member("paymentMethods");
		this.payment_methods = new PaymentMethod[paymentMethods.get_length()];
		paymentMethods.foreach_element((ar, i, el) => {
			var ob = el.get_object();
			var payment_method = PaymentMethod() {
				type = ob.get_string_member("type"),
				nonce = ob.get_string_member("nonce"),
				description = ob.get_string_member("description"),
				is_default = ob.get_boolean_member("default")
			};
			switch (payment_method.type) {
				case "CreditCard":
					var details = ob.get_object_member("details");
					payment_method.card_type = details.get_string_member("cardType");
					//var last_two = details.get_string_member("lastTwo");
					//stdout.printf("  details: type=%s|last_two=%s\n", card_type, last_two);
					break;
			}
			this.payment_methods[i] = payment_method;
		});
	}

	public async CreateCreditCardResult create_credit_card(HashTable<string, string> parameters) throws Error {
		if (!this.initialized) {
			throw new ApiError.NOT_INITIALIZED("not initialized");
		}

		var uri = new Soup.URI(this.client_api_url + "/v1/payment_methods/credit_cards");
		uri.set_query_from_fields("authorizationFingerprint", this.authorization_fingerprint);

		foreach (var k in parameters.get_keys_as_array()) {
			parameters.insert("credit_card[" + k + "]", parameters.@get(k));
			parameters.remove(k);
		}
		parameters.insert("_meta[integration]", "custom");
		parameters.insert("_meta[source]", "form");
		var msg = Soup.Form.request_new_from_hash("POST", uri.to_string(false), parameters);

		var parser = new Json.Parser();
		yield parser.load_from_stream_async(yield this.session.send_async(msg));
		var root = parser.get_root().get_object();

		if (msg.status_code != Soup.Status.CREATED) {
			// {"error":{"message":"Credit card is invalid"},"fieldErrors":[{"field":"creditCard","fieldErrors":[{"field":"number","code":"81716","message":"Credit card number must be 12-19 digits"}]}]}
			var error = root.get_object_member("error");
			var error_message = error.get_string_member("message");

			var errors = new Gee.ArrayList<FieldError>();
			root.get_array_member("fieldErrors").get_object_element(0).get_array_member("fieldErrors").foreach_element((ar, i, el) => {
				var ob = el.get_object();
				errors.add(new FieldError(ob.get_string_member("field"), ob.get_string_member("message")));
			});
			return new CreateCreditCardResult.with_errors(error_message, errors);
		}

		// {"creditCards":[{"type":"CreditCard","nonce":"d2b5d098-768e-4ca6-b3ea-79b418a973e8","description":"ending in 11","consumed":false,"threeDSecureInfo":null,"details":{"lastTwo":"11","cardType":"Visa"}}]}
		var credit_cards = root.get_array_member("creditCards");
		var nonce = credit_cards.get_object_element(0).get_string_member("nonce");

		return new CreateCreditCardResult.with_success(nonce);
	}

	public class CreateCreditCardResult {
		public bool success { get; private set; }
		public string error_message { get; private set; }
		public Gee.ArrayList<FieldError> errors { get; private set; }
		public string nonce { get; private set; }

		public CreateCreditCardResult.with_success(string nonce) {
			this.success = true;
			this.nonce = nonce;
		}

		public CreateCreditCardResult.with_errors(string error_message, Gee.ArrayList<FieldError> errors) {
			this.success = false;
			this.error_message = error_message;
			this.errors = errors;
		}
	}

	public class FieldError {
		public string field { get; private set; }
		public string message { get; private set; }

		public FieldError(string field, string message) {
			this.field = field;
			this.message = message;
		}
	}

	public enum Environment {
		DEVELOPMENT,
		SANDBOX,
		PRODUCTION;

		public string base_url() {
			switch (this) {
				case DEVELOPMENT:
					return "http://localhost:3000";

				case SANDBOX:
					return "https://sandbox.braintreegateway.com";

				case PRODUCTION:
					return "https://www.braintreegateway.com";

				default:
					assert_not_reached();
			}
		}
	}

	public class ClientTokenGateway {
		private Braintree bt;

		public ClientTokenGateway(Braintree bt) {
			this.bt = bt;
		}

		public async string generate(string? customer_id) throws Error {
			string xml;
			Xml.Doc *request_doc = new Xml.Doc("1.0");
			Xml.Node *root = new Xml.Node(null, "client_token");
			request_doc->set_root_element(root);
			root->new_text_child(null, "version", "2")->new_prop("type", "integer");
			root->new_text_child(null, "merchant-account-id", bt.merchant_id);
			if (customer_id != null) {
				root->new_text_child(null, "customer-id", customer_id);
			}
			// Xml.Node *options = root->new_child(null, "options");
			// options->new_text_child(null, "verify-card", "true")->new_prop("type", "boolean");
			request_doc->dump_memory(out xml);
			delete request_doc;

			var result = yield this.bt.execute("POST", "client_token", xml);
			if (result.status_code != Soup.Status.CREATED) {
				throw new ApiError.UNEXPECTED_RESPONSE("Unexpected response: " + result.status_code.to_string());
			}

			Xml.Doc *result_doc = yield this.bt.parse_xml_from_stream(result.stream);
			Xml.XPath.Object *query = (new Xml.XPath.Context(result_doc)).eval_expression("/client-token/value");
			string client_token = query->nodesetval->item(0)->get_content();

			delete result_doc;
			delete query;
			return client_token;
		}
	}

	public class TransactionGateway {
		private Braintree bt;

		public TransactionGateway(Braintree bt) {
			this.bt = bt;
		}

		public async string sale(Sale *sale) throws Error {
			string xml;
			Xml.Doc *request_doc = new Xml.Doc("1.0");
			Xml.Node *root = new Xml.Node(null, "transaction");
			request_doc->set_root_element(root);
			root->new_text_child(null, "type", "sale");
			root->new_text_child(null, "amount", sale->amount);
			root->new_text_child(null, "payment-method-nonce", sale->nonce);

			Xml.Node *options = root->new_child(null, "options");
			options->new_text_child(null, "submit-for-settlement", "true")->set_prop("type", "boolean");
			//options->new_text_child(null, "store-in-vault-on-success", sale->store_in_vault.to_string())->set_prop("type", "boolean");

			request_doc->dump_memory(out xml);
			delete request_doc;

			var result = yield this.bt.execute("POST", "transactions", xml);
			if (result.status_code != Soup.Status.CREATED) {
				yield this.bt.throw_error_for_result(result);
			}

			Xml.Doc *result_doc = yield this.bt.parse_xml_from_stream(result.stream);
			Xml.XPath.Object *query = (new Xml.XPath.Context(result_doc)).eval_expression("/transaction/id");
			string transaction_id = query->nodesetval->item(0)->get_content();

			delete result_doc;
			delete query;
			return transaction_id;
		}
	}

	protected async ApiResult execute(string method, string path, string? xml) throws Error {
		var msg = new Soup.Message("POST", this.merchant_url + "/" + path);
		msg.request_headers.append("Accept", "application/xml");
		msg.request_headers.append("Accept-Encoding", "gzip");
		msg.request_headers.append("User-Agent", "Braintree GTK+");
		msg.request_headers.append("X-ApiVersion", "3");
		msg.request_headers.append("Content-Type", "application/xml");

		if (xml != null) {
			msg.set_request("application/xml", Soup.MemoryUse.TEMPORARY, xml.data);
		}

		var stream = yield this.session.send_async(msg, null);
		return { msg.status_code, msg.response_headers.get_content_type(null), stream };
	}

	protected async void throw_error_for_result(ApiResult result) throws Error {
		if (result.content_type != "application/xml") {
			throw new ApiError.UNEXPECTED_RESPONSE("Unexpected response: " + result.status_code.to_string());
		}
		Xml.Doc *doc = yield this.parse_xml_from_stream(result.stream);
		// NOTE: This <api-error-response> document contains more granular information that can be accessed
		// on the individual objects; for example, "CVV is required" would be on transaction -> credit-card.
		// For now, we don't really care about actually parsing this.
		Xml.XPath.Object *query = (new Xml.XPath.Context(doc)).eval_expression("/api-error-response/message");
		string error_message = query->nodesetval->item(0)->get_content();
		delete doc;
		delete query;
		throw new ApiError.ERROR_RESPONSE(error_message);
	}

	private async Xml.Doc *parse_xml_from_stream(InputStream stream) throws Error {
		var buffer = new uint8[4096];
		var array = new ByteArray();
		ssize_t bytes_read;
		while ((bytes_read = yield stream.read_async(buffer, Priority.HIGH)) > 0) {
			array.append(buffer[0:bytes_read]);
		}
		// stdout.printf("%s\n\n", (string)array.data);
		return Xml.Parser.parse_memory((string)array.data, (int)array.len);
	}

	// This is just here for debugging purposes.
	public async string read_whole_stream(InputStream stream) throws Error {
		var buffer = new uint8[4096];
		var array = new ByteArray();
		ssize_t bytes_read;
		while ((bytes_read = yield stream.read_async(buffer, Priority.HIGH)) > 0) {
			array.append(buffer[0:bytes_read]);
		}
		return (string)array.data;
	}

	protected struct ApiResult {
		uint status_code;
		string? content_type;
		InputStream stream;
	}
}

errordomain UsageError {
	NOT_DEFINED
}

errordomain ApiError {
	NOT_INITIALIZED,
	ERROR_RESPONSE,
	UNEXPECTED_RESPONSE
}

delegate void NonceHandler(string nonce);

void display_message(Gtk.Box window_top_box, Gtk.MessageType message_type, string message) {
	var infobar = new Gtk.InfoBar();
	infobar.set_message_type(message_type);
	infobar.get_content_area().add(new Gtk.Label(message));
	infobar.set_show_close_button(true);
	infobar.response.connect((response_id) => {
		switch (response_id) {
			case Gtk.ResponseType.CLOSE:
				window_top_box.remove(infobar);
				break;
		}
	});
	infobar.close.connect(() => {
		window_top_box.remove(infobar);
	});
	window_top_box.pack_start(infobar);
	infobar.show_all();
}

int main(string[] args) {
	Braintree.Environment? environment = null;
	switch (GLib.Environment.get_variable("ENVIRONMENT")) {
		case "sandbox":
			environment = Braintree.Environment.SANDBOX;
			break;
		case "production":
			environment = Braintree.Environment.PRODUCTION;
			break;
		default:
			throw new UsageError.NOT_DEFINED("environment variable `ENVIRONMENT' invalid or not defined");
	}
	var bt = new Braintree(
		environment,
		GLib.Environment.get_variable("MERCHANT_ID"),
		GLib.Environment.get_variable("PUBLIC_KEY"),
		GLib.Environment.get_variable("PRIVATE_KEY")
	);

	Gtk.init(ref args);

	var window = new Gtk.Window();
	window.title = "Credit Card";
	window.default_width = 200;
	window.default_height = 200;
	window.window_position = Gtk.WindowPosition.CENTER;
	window.destroy.connect(Gtk.main_quit);

	var payment_methods_box = new Gtk.Box(Gtk.Orientation.VERTICAL, 6);
	//var enter_new_card = new Gtk.Button.from_icon_name("list-add");
	var enter_new_card = new Gtk.Button.with_label("Add New Card");
	// payment_methods_box.pack_start(new Gtk.Label("Payment Methods"), false, false, 6);
	payment_methods_box.pack_end(enter_new_card, false, false, 6);

	var new_credit_card_box = new Gtk.Box(Gtk.Orientation.VERTICAL, 6);
	var credit_card = new CreditCard();
	var new_payment_method_back = new Gtk.Button.from_icon_name("go-previous");
	new_credit_card_box.pack_start(new_payment_method_back, false, false, 6);
	new_credit_card_box.pack_start(credit_card, false, false, 6);

	var payment_stack = new Gtk.Stack();
	payment_stack.add_named(new Gtk.Label("Initializing..."), "loading");
	payment_stack.add_named(payment_methods_box, "payment_methods");
	payment_stack.add_named(new_credit_card_box, "new_card");

	var amount = new Gtk.Entry();
	var submit_box = new Gtk.Box(Gtk.Orientation.HORIZONTAL, 6);
	var submit = new Gtk.Button.with_label("Submit");
	amount.text = "100"; // DELETEME
	amount.placeholder_text = "Transaction Amount";
	submit.get_style_context().add_class("suggested-action");
	submit_box.pack_start(amount, true, true, 6);
	submit_box.pack_end(submit, false, false, 6);

	var window_box = new Gtk.Box(Gtk.Orientation.VERTICAL, 6);
	window_box.margin_start = 18;
	window_box.margin_end = 18;
	window_box.pack_start(payment_stack);
	window_box.pack_start(new Gtk.Separator(Gtk.Orientation.HORIZONTAL));
	var window_top_box = new Gtk.Box(Gtk.Orientation.VERTICAL, 6);
	window_top_box.pack_end(window_box);
	window.add(window_top_box);
	window.show_all();

	var using_new_payment_method = false;

	NonceHandler transact = (nonce) => {
		var sale = Sale() {
			nonce = nonce,
			amount = amount.text
		};
		bt.transaction.sale.begin(&sale, (obj, resp) => {
			try {
				var transaction_id = bt.transaction.sale.end(resp);
				display_message(window_top_box, Gtk.MessageType.INFO, "Transaction ID: " + transaction_id);
			}
			catch (ApiError e) {
				display_message(window_top_box, Gtk.MessageType.INFO, e.message);
			}
			catch (Error e) {
				display_message(window_top_box, Gtk.MessageType.INFO, "An unexpected error occurred: " + e.message);
			}
			finally {
				submit.set_sensitive(true);
			}
		});
	};

	submit.clicked.connect(() => {
		submit.set_sensitive(false);
		if (using_new_payment_method) {
			// Create a new credit card.
			bt.create_credit_card.begin(credit_card.parameters, (obj, resp) => {
				credit_card.clear_errors();

				try {
					var result = bt.create_credit_card.end(resp);
					if (result.success) {
						transact(result.nonce);
					} else {
						display_message(window_top_box, Gtk.MessageType.ERROR, "Review the errors and try again.");
						stdout.printf("No dice.\n");
						result.errors.@foreach((error) => {
							credit_card.show_error(error.field, error.message);
							return true;
						});
						submit.set_sensitive(true);
					}
				}
				catch (Error e) {
					display_message(window_top_box, Gtk.MessageType.ERROR, "An error occurred: " + e.message);
					submit.set_sensitive(true);
				}
			});
		} else {
			// Use an existing payment method.
			for (var i = 0; i < bt.payment_methods.length; i++) {
				if (bt.payment_method_buttons[i].active) {
					transact(bt.payment_methods[i].nonce);
					break;
				}
			}
		}
	});

	bt.init.begin(GLib.Environment.get_variable("CUSTOMER_ID"), (obj, resp) => {
		try {
			bt.init.end(resp);
			bt.payment_method_buttons = new Gtk.RadioButton[bt.payment_methods.length];
			for (var i = 0; i < bt.payment_methods.length; i++) {
				var is_default = bt.payment_methods[i].is_default;
				var btn = new Gtk.RadioButton.with_label_from_widget(
					bt.payment_method_buttons[0],
					bt.payment_methods[i].type + " " + bt.payment_methods[i].description + (is_default ? " (default)" : "")
				);
				btn.set_always_show_image(true);
				btn.set_image_position(Gtk.PositionType.LEFT);
				switch (bt.payment_methods[i].type) {
					case "CreditCard":
						switch (bt.payment_methods[i].card_type) {
							case "Discover":
								btn.set_image(CreditCardLogo.discover());
								break;
							case "Visa":
								btn.set_image(CreditCardLogo.visa());
								break;
							case "MasterCard":
								btn.set_image(CreditCardLogo.mastercard());
								break;
							case "JCB":
								btn.set_image(CreditCardLogo.jcb());
								break;
							case "American Express":
								btn.set_image(CreditCardLogo.amex());
								break;
							default:
								stderr.printf("unknown credit card type: %s\n", bt.payment_methods[i].card_type);
								break;
						}
						break;
				}
				payment_methods_box.pack_start(btn, false, false, 0);
				btn.set_active(bt.payment_methods[i].is_default);
				bt.payment_method_buttons[i] = btn;
			}
			payment_methods_box.valign = Gtk.Align.CENTER;
			window_box.pack_start(submit_box, false, false, 6);
			window_box.show_all();

			credit_card.set_challenges(bt.challenges);
			payment_stack.set_visible_child_name("payment_methods");
			enter_new_card.clicked.connect(() => {
				using_new_payment_method = true;
				payment_stack.set_visible_child_name("new_card");
			});
			new_payment_method_back.clicked.connect(() => {
				using_new_payment_method = false;
				payment_stack.set_visible_child_name("payment_methods");
			});
		}
		catch (Error e) {
			display_message(window_top_box, Gtk.MessageType.ERROR, "An error occurred: " + e.message);
		}
	});

	Gtk.main();
	return 0;
}
