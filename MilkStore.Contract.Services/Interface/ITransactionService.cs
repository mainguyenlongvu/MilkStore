using MilkStore.Contract.Repositories.Entity;
using MilkStore.Core;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.ModelViews.ResponseDTO;
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
        Task<string> Topup(double amount);
        Task<BasePaginatedList<TransactionHistoryResponseDTO>> GetPersonalTransactionHistory(TransactionType? transactionType, DateTime? fromDate, DateTime? toDate, int? month, int? year, int pageIndex, int pageSize);
        Task<BasePaginatedList<TransactionHistoryResponseDTO>> GetAllTransactionHistoryAsync(string? userId, TransactionType? transactionType, DateTime? fromDate, DateTime? toDate, int? month, int? year, int pageIndex, int pageSize);
    }
}
