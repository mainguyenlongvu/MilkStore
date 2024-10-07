using MilkStore.ModelViews;

public interface IPaymentService
{
    public string CreatePayment(PaymentRequest request);
    public Task HandleIPN(VNPayIPNRequest request);
}