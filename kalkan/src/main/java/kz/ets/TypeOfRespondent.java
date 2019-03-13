package kz.ets;

public enum TypeOfRespondent {

    FIRM(1), PERSON(2);
    private final int code;

    TypeOfRespondent(int aCode) {
        this.code = aCode;
    }

    public int getCode() {
        return code;
    }

    public static TypeOfRespondent findByCode(int seekCode) {
        for (TypeOfRespondent seekType : TypeOfRespondent.values()) {
            if (seekType.getCode() == seekCode) {
                return seekType;
            }
        }
        return null;
    }

}
