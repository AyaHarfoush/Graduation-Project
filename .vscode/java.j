public class TransactionSystem {

    public static void main(String[] args) {

        //ARRAY of accounts
        double[] accounts = {1000, 500, 800, 1200, 300};

        printAccounts(accounts);

        // DEPOSIT
        deposit(accounts, 0, 200);
        printAccounts(accounts);

        // WITHDRAW
        withdraw(accounts, 1, 100);
        printAccounts(accounts);

        //  TRANSFER 
        transfer(accounts, 2, 4, 250);
        printAccounts(accounts);

        //  FAILED WITHDRAW (ROLLBACK)
        withdraw(accounts, 4, 1000);
        printAccounts(accounts);
    }

    //  DEPOSIT FUNCTION
    public static void deposit(double[] accounts, int acc, double amount) {

        System.out.println("\nDeposit:");

        if (amount > 0) {
            accounts[acc] = accounts[acc] + amount;
            System.out.println("Success");
        } else {
            System.out.println("Failed");
        }
    }

    //WITHDRAW FUNCTION
    public static void withdraw(double[] accounts, int acc, double amount) {

        System.out.println("\nWithdraw:");

        double old = accounts[acc]; // حفظ القيمة

        if (amount > 0 && accounts[acc] >= amount) {
            accounts[acc] = accounts[acc] - amount;
            System.out.println("Success");
        } else {
            accounts[acc] = old; // rollback
            System.out.println("Failed -> Rollback");
        }
    }

    // TRANSFER FUNCTION 
    public static void transfer(double[] accounts, int from, int to, double amount) {

        System.out.println("\nTransfer:");

        double oldFrom = accounts[from];
        double oldTo = accounts[to];

        if (amount > 0 && accounts[from] >= amount) {
            accounts[from] = accounts[from] - amount;
            accounts[to] = accounts[to] + amount;
            System.out.println("Success");
        } else {
            accounts[from] = oldFrom;
            accounts[to] = oldTo;
            System.out.println("Failed -> Rollback");
        }
    }

    //PRINT FUNCTION
    public static void printAccounts(double[] accounts) {

        System.out.println("\nAccounts:");

        for (int i = 0; i < accounts.length; i++) {
            System.out.println("Account " + i + ": " + accounts[i]);
        }
    }
}