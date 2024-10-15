using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.OrderModelViews;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface ITransactionService
    {
        Task<string> Checkout(PaymentMethod paymentMethod, List<string>? voucherCode, ShippingType shippingAddress);
    }
}
