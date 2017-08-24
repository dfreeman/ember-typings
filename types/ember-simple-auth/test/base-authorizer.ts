import BaseAuthorizer from "ember-simple-auth/authorizers/base";

class MyAuthorizer extends BaseAuthorizer {
    foo() {
        this.authorize({}, (key, value) => {
            console.log(`header: ${key}, value: ${value}`);
        });
    }
}
